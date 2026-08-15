import boto3
from urllib.parse import unquote

from scanner.models import Finding


def scan_iam(resource, severity):

    iam = boto3.client("iam")

    try:
        findings = []

        RISK_SCORES = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4
        }

        def save_finding(
            score,
            severity_level,
            policy_name,
            message,
            recommendation,
            policy_type,
            attached_to
        ):
            findings.append(
                {
                    "score": score,
                    "severity": severity_level,
                    "policy": policy_name,
                    "message": message,
                    "recommendation": recommendation,
                    "policy_type": policy_type,
                    "attached_to": attached_to
                }
            )

        def classify_actions(
            policy_name,
            actions,
            resources,
            policy_type,
            attached_to
        ):

            resource_wildcard = "*" in resources

            # =========================================
            # 1. FULL ACTION WILDCARD
            #
            # Action: *
            # Resource: *
            # =========================================

            if "*" in actions and resource_wildcard:

                save_finding(
                    4,
                    "CRITICAL",
                    policy_name,
                    (
                        f'Policy "{policy_name}" allows '
                        f'wildcard action "*" on all resources'
                    ),
                    (
                        "Restrict IAM actions and resources "
                        "to only those required"
                    ),
                    policy_type,
                    attached_to
                )

                return

            # =========================================
            # 2. SERVICE-LEVEL WILDCARD
            #
            # Example:
            # s3:*
            # iam:*
            # ec2:*
            # =========================================

            service_wildcards = [
                action
                for action in actions
                if action.endswith(":*")
            ]

            if service_wildcards and resource_wildcard:

                save_finding(
                    3,
                    "HIGH",
                    policy_name,
                    (
                        f'Policy "{policy_name}" allows '
                        f'{", ".join(service_wildcards)} '
                        f'on all resources'
                    ),
                    (
                        "Restrict service-level actions "
                        "and resource scope to only those required"
                    ),
                    policy_type,
                    attached_to
                )

                return

            # =========================================
            # 3. BROAD ACTION WILDCARDS
            #
            # Examples:
            # s3:Get*
            # s3:List*
            # iam:Get*
            # iam:List*
            # =========================================

            broad_actions = [
                action
                for action in actions
                if "*" in action
            ]

            if broad_actions and resource_wildcard:

                save_finding(
                    2,
                    "MEDIUM",
                    policy_name,
                    (
                        f'Policy "{policy_name}" allows '
                        f'{", ".join(broad_actions)} '
                        f'on all resources'
                    ),
                    (
                        "Restrict the resource scope "
                        "to only those required"
                    ),
                    policy_type,
                    attached_to
                )

                return

            # =========================================
            # 4. SPECIFIC ACTION + WILDCARD RESOURCE
            #
            # Example:
            # s3:GetObject
            # Resource: *
            # =========================================

            if resource_wildcard:

                save_finding(
                    1,
                    "LOW",
                    policy_name,
                    (
                        f'Policy "{policy_name}" allows '
                        f'{", ".join(actions)} '
                        f'on all resources'
                    ),
                    (
                        "Review whether wildcard resource "
                        "scope is required"
                    ),
                    policy_type,
                    attached_to
                )

        def analyze_policy_document(
            policy_name,
            document,
            policy_type,
            attached_to
        ):

            if isinstance(document, str):
                document = unquote(document)

            statements = document.get("Statement", [])

            if isinstance(statements, dict):
                statements = [statements]

            for statement in statements:

                if statement.get("Effect") != "Allow":
                    continue

                actions = statement.get("Action", [])

                if isinstance(actions, str):
                    actions = [actions]

                resources = statement.get("Resource", [])

                if isinstance(resources, str):
                    resources = [resources]

                classify_actions(
                    policy_name,
                    actions,
                    resources,
                    policy_type,
                    attached_to
                )

        # =================================================
        # 1. DIRECT USER MANAGED POLICIES
        # =================================================

        user_policies = iam.list_attached_user_policies(
            UserName=resource
        )

        for policy in user_policies["AttachedPolicies"]:

            policy_name = policy["PolicyName"]

            if policy_name == "AdministratorAccess":

                save_finding(
                    4,
                    "CRITICAL",
                    policy_name,
                    (
                        "IAM user has AdministratorAccess "
                        "permissions"
                    ),
                    (
                        "Follow the principle of least privilege"
                    ),
                    "User Managed Policy",
                    resource
                )

                continue

            policy_response = iam.get_policy(
                PolicyArn=policy["PolicyArn"]
            )

            default_version = (
                policy_response["Policy"]["DefaultVersionId"]
            )

            version_response = iam.get_policy_version(
                PolicyArn=policy["PolicyArn"],
                VersionId=default_version
            )

            document = (
                version_response["PolicyVersion"]["Document"]
            )

            analyze_policy_document(
                policy_name,
                document,
                "User Managed Policy",
                resource
            )

        # =================================================
        # 2. USER INLINE POLICIES
        # =================================================

        inline_policies = iam.list_user_policies(
            UserName=resource
        )

        for policy_name in inline_policies["PolicyNames"]:

            inline_response = iam.get_user_policy(
                UserName=resource,
                PolicyName=policy_name
            )

            document = inline_response["PolicyDocument"]

            analyze_policy_document(
                policy_name,
                document,
                "User Inline Policy",
                resource
            )

        # =================================================
        # 3. GROUP POLICIES
        # =================================================

        groups_response = iam.list_groups_for_user(
            UserName=resource
        )

        for group in groups_response["Groups"]:

            group_name = group["GroupName"]

            # =============================================
            # 3A. GROUP INLINE POLICIES
            # =============================================

            group_inline_policies = iam.list_group_policies(
                GroupName=group_name
            )

            for policy_name in group_inline_policies["PolicyNames"]:

                inline_response = iam.get_group_policy(
                    GroupName=group_name,
                    PolicyName=policy_name
                )

                document = inline_response["PolicyDocument"]

                analyze_policy_document(
                    policy_name,
                    document,
                    "Group Inline Policy",
                    group_name
                )

            # =============================================
            # 3B. GROUP MANAGED POLICIES
            # =============================================

            group_policies = iam.list_attached_group_policies(
                GroupName=group_name
            )

            for policy in group_policies["AttachedPolicies"]:

                policy_name = policy["PolicyName"]

                if policy_name == "AdministratorAccess":

                    save_finding(
                        4,
                        "CRITICAL",
                        policy_name,
                        (
                            "IAM user receives "
                            "AdministratorAccess through a group"
                        ),
                        (
                            "Follow the principle of least privilege"
                        ),
                        "Group Managed Policy",
                        group_name
                    )

                    continue

                policy_response = iam.get_policy(
                    PolicyArn=policy["PolicyArn"]
                )

                default_version = (
                    policy_response["Policy"]["DefaultVersionId"]
                )

                version_response = iam.get_policy_version(
                    PolicyArn=policy["PolicyArn"],
                    VersionId=default_version
                )

                document = (
                    version_response["PolicyVersion"]["Document"]
                )

                analyze_policy_document(
                    policy_name,
                    document,
                    "Group Managed Policy",
                    group_name
                )

        # =================================================
        # 4. NO FINDINGS
        # =================================================

        if not findings:

            return Finding(
                service="IAM",
                resource=resource,
                status="PASS",
                severity="LOW",
                message=(
                    "IAM user permissions do not contain "
                    "high-risk wildcard patterns"
                ),
                recommendation="No action required"
            )

        # =================================================
        # 5. DETERMINE HIGHEST SEVERITY
        # =================================================

        highest_finding = max(
            findings,
            key=lambda finding: finding["score"]
        )

        highest_severity = highest_finding["severity"]

        # =================================================
        # 6. BUILD SUMMARY
        # =================================================

        summary_lines = [
            f"{len(findings)} IAM security issue(s) detected:"
        ]

        for index, finding in enumerate(findings, start=1):

            summary_lines.append(
                (
                    f"{index}. "
                    f"{finding['severity']} - "
                    f"{finding['policy']} | "
                    f"Type: {finding['policy_type']} | "
                    f"Attached To: {finding['attached_to']} | "
                    f"{finding['message']}"
                )
            )

        message = "\n".join(summary_lines)

        # =================================================
        # 7. COMBINE RECOMMENDATIONS
        # =================================================

        if highest_severity == "CRITICAL":

           recommendation = (
             "Immediately review and restrict critical IAM "
             "permissions according to the principle of least privilege."
            )

        elif highest_severity == "HIGH":

            recommendation = (
              "Review and restrict high-risk IAM permissions "
              "according to the principle of least privilege."
         )

        elif highest_severity == "MEDIUM":

            recommendation = (
              "Review broad IAM permissions and restrict "
              "resource scope where possible."
        )

        else:

            recommendation = (
              "Review IAM permissions and apply the principle "
              "of least privilege."
            )
        # =================================================
        # 8. RETURN ONE IAM FINDING
        # =================================================

        return Finding(
            service="IAM",
            resource=resource,
            status="FAIL",
            severity=highest_severity,
            message=message,
            recommendation=recommendation
        )

    except Exception as e:

        return Finding(
            service="IAM",
            resource=resource,
            status="ERROR",
            severity="HIGH",
            message=(
                f"Unable to check IAM permissions: {str(e)}"
            ),
            recommendation="Verify AWS IAM permissions"
        )
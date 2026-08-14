import boto3
from urllib.parse import unquote

from scanner.models import Finding


def scan_iam(resource, severity):

    iam = boto3.client("iam")

    try:
        best_finding = None
        best_score = 0

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
            recommendation
        ):
            nonlocal best_finding
            nonlocal best_score

            if score > best_score:

                best_score = score

                best_finding = {
                    "severity": severity_level,
                    "policy": policy_name,
                    "message": message,
                    "recommendation": recommendation
                }

        def classify_actions(
            policy_name,
            actions,
            resources
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
                    )
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
                    )
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
                    )
                )

                return

            # =========================================
            # 4. SPECIFIC ACTION + WILDCARD RESOURCE
            #
            # Example:
            # s3:GetObject
            # Resource: *
            #
            # Lower risk, but worth reviewing.
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
                    )
                )

        def analyze_policy_document(
            policy_name,
            document
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
                    resources
                )

        # =================================================
        # 1. DIRECT USER POLICIES
        # =================================================

        user_policies = iam.list_attached_user_policies(
            UserName=resource
        )

        for policy in user_policies["AttachedPolicies"]:

            policy_name = policy["PolicyName"]

            # AdministratorAccess is always treated
            # as a critical finding.
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
                    )
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
                document
            )

        # =================================================
        # 2. GROUP POLICIES
        # =================================================

        groups_response = iam.list_groups_for_user(
            UserName=resource
        )

        for group in groups_response["Groups"]:

            group_policies = iam.list_attached_group_policies(
                GroupName=group["GroupName"]
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
                        )
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
                    document
                )

        # =================================================
        # 3. INLINE POLICIES
        # =================================================

        inline_policies = iam.list_user_policies(
            UserName=resource
        )

        if inline_policies["PolicyNames"]:

            save_finding(
                1,
                "LOW",
                "Inline Policy",
                (
                    "IAM user has inline policies "
                    "that require review"
                ),
                (
                    "Review inline policies and use "
                    "managed policies where appropriate"
                )
            )

        # =================================================
        # 4. RETURN HIGHEST-RISK FINDING
        # =================================================

        if best_finding:

            return Finding(
                service="IAM",
                resource=resource,
                status="FAIL",
                severity=best_finding["severity"],
                message=best_finding["message"],
                recommendation=best_finding["recommendation"]
            )

        # =================================================
        # 5. EVERYTHING LOOKS OK
        # =================================================

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
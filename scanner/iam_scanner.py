import boto3
from urllib.parse import unquote

from scanner.models import Finding


def scan_iam(resource, severity):

    iam = boto3.client("iam")

    try:

        # =================================================
        # FINDINGS STORAGE
        # =================================================

        findings = []

        # =================================================
        # SAVE FINDING
        # =================================================

        def save_finding(
            score,
            severity_level,
            policy_name,
            policy_type,
            attached_to,
            message,
            recommendation
        ):

            findings.append({
                "score": score,
                "severity": severity_level,
                "policy": policy_name,
                "policy_type": policy_type,
                "attached_to": attached_to,
                "message": message,
                "recommendation": recommendation
            })

        # =================================================
        # ARN PARSER
        # =================================================

        def parse_arn(resource_arn):

            if not isinstance(resource_arn, str):
                return None

            if not resource_arn.startswith("arn:"):
                return None

            parts = resource_arn.split(":", 5)

            if len(parts) != 6:
                return None

            return {
                "partition": parts[1],
                "service": parts[2],
                "region": parts[3],
                "account": parts[4],
                "resource": parts[5]
            }

        # =================================================
        # RESOURCE + ACTION ANALYSIS
        # =================================================

        def analyze_resources(
            policy_name,
            policy_type,
            attached_to,
            actions,
            resources
        ):

            # -------------------------------------------------
            # Determine resource scope
            # -------------------------------------------------

            resource_wildcard = "*" in resources

            # -------------------------------------------------
            # Parse scoped ARNs
            # -------------------------------------------------

            scoped_resources = [
                resource
                for resource in resources
                if resource != "*"
            ]

            parsed_resources = []

            for resource_arn in scoped_resources:

                parsed = parse_arn(resource_arn)

                if parsed:
                    parsed_resources.append(parsed)

            # -------------------------------------------------
            # CASE 1
            # Action "*" + Resource "*"
            # -------------------------------------------------

            if "*" in actions and resource_wildcard:

                save_finding(
                    4,
                    "CRITICAL",
                    policy_name,
                    policy_type,
                    attached_to,
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

            # -------------------------------------------------
            # CASE 2
            # Service-level wildcard
            #
            # Examples:
            # s3:*
            # iam:*
            # ec2:*
            #
            # Resource: *
            # -------------------------------------------------

            service_wildcards = [
                action
                for action in actions
                if isinstance(action, str)
                and action.endswith(":*")
            ]

            if service_wildcards and resource_wildcard:

                save_finding(
                    3,
                    "HIGH",
                    policy_name,
                    policy_type,
                    attached_to,
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

            # -------------------------------------------------
            # CASE 3
            # Broad action wildcard
            #
            # Examples:
            # s3:Get*
            # s3:List*
            # iam:Get*
            #
            # Resource: *
            # -------------------------------------------------

            broad_actions = [
                action
                for action in actions
                if isinstance(action, str)
                and "*" in action
            ]

            if broad_actions and resource_wildcard:

                save_finding(
                    2,
                    "MEDIUM",
                    policy_name,
                    policy_type,
                    attached_to,
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

            # -------------------------------------------------
            # CASE 4
            # Specific action + wildcard resource
            #
            # Example:
            # s3:GetObject
            #
            # Resource: *
            # -------------------------------------------------

            if resource_wildcard:

                save_finding(
                    2,
                    "MEDIUM",
                    policy_name,
                    policy_type,
                    attached_to,
                    (
                        f'Policy "{policy_name}" allows '
                        f'{", ".join(actions)} '
                        f'on all resources'
                    ),
                    (
                        "Restrict the resource scope "
                        "to only the required resources"
                    )
                )

                return

            # -------------------------------------------------
            # CASE 5
            # Scoped resource ARN
            #
            # Example:
            # arn:aws:s3:::bucket-name/*
            #
            # Properly scoped resources are not considered
            # security findings.
            # -------------------------------------------------

            # We parse the ARNs so that later versions of
            # CloudSentinel can validate service/resource
            # matching.

            for parsed in parsed_resources:

                service = parsed["service"]
                resource_name = parsed["resource"]

                # Currently no finding is generated.
                # This is intentionally considered safe.

                _ = service
                _ = resource_name

        # =================================================
        # CONDITION ANALYSIS
        # =================================================

        def analyze_conditions(
            policy_name,
            policy_type,
            attached_to,
            condition
        ):

            if not condition:
                return

            for operator, condition_values in condition.items():

                if not isinstance(condition_values, dict):
                    continue

                for key, value in condition_values.items():

                    print(
                        f"Condition detected: "
                        f"{operator} -> {key} = {value}"
                    )

        # =================================================
        # POLICY DOCUMENT ANALYSIS
        # =================================================

        def analyze_policy_document(
            policy_name,
            policy_type,
            attached_to,
            document
        ):

            # -------------------------------------------------
            # URL-decode policy document if necessary
            # -------------------------------------------------

            if isinstance(document, str):

                document = unquote(document)

                if not isinstance(document, dict):
                    return

            # -------------------------------------------------
            # Get statements
            # -------------------------------------------------

            statements = document.get(
                "Statement",
                []
            )

            # AWS allows Statement to be either:
            #
            # "Statement": {...}
            #
            # OR
            #
            # "Statement": [{...}, {...}]
            # -------------------------------------------------

            if isinstance(statements, dict):

                statements = [statements]

            # -------------------------------------------------
            # Analyze each statement
            # -------------------------------------------------

            for statement in statements:

                if not isinstance(statement, dict):
                    continue

                effect = statement.get(
                    "Effect"
                )

                # -------------------------------------------------
                # DENY STATEMENT
                # -------------------------------------------------

                if effect == "Deny":

                    # We currently do not create findings
                    # for explicit Deny statements because
                    # Deny is normally a security control.

                    continue

                # -------------------------------------------------
                # ONLY ANALYZE ALLOW STATEMENTS
                # -------------------------------------------------

                if effect != "Allow":
                    continue

                # -------------------------------------------------
                # ACTION
                # -------------------------------------------------

                actions = statement.get(
                    "Action",
                    []
                )

                if isinstance(actions, str):

                    actions = [actions]

                # -------------------------------------------------
                # RESOURCE
                # -------------------------------------------------

                resources = statement.get(
                    "Resource",
                    []
                )

                if isinstance(resources, str):

                    resources = [resources]

                # -------------------------------------------------
                # CONDITION
                # -------------------------------------------------

                conditions = statement.get(
                    "Condition",
                    {}
                )

                # -------------------------------------------------
                # ANALYZE CONDITIONS
                # -------------------------------------------------

                analyze_conditions(
                    policy_name,
                    policy_type,
                    attached_to,
                    conditions
                )

                # -------------------------------------------------
                # ANALYZE ACTION + RESOURCE
                # -------------------------------------------------

                analyze_resources(
                    policy_name,
                    policy_type,
                    attached_to,
                    actions,
                    resources
                )

        # =================================================
        # 1. DIRECT USER MANAGED POLICIES
        # =================================================

        user_policies = iam.list_attached_user_policies(
            UserName=resource
        )

        for policy in user_policies["AttachedPolicies"]:

            policy_name = policy["PolicyName"]

            # -------------------------------------------------
            # AdministratorAccess
            # -------------------------------------------------

            if policy_name == "AdministratorAccess":

                save_finding(
                    4,
                    "CRITICAL",
                    policy_name,
                    "User Managed Policy",
                    resource,
                    (
                        "IAM user has AdministratorAccess "
                        "permissions"
                    ),
                    (
                        "Follow the principle of least privilege"
                    )
                )

                continue

            # -------------------------------------------------
            # Get policy
            # -------------------------------------------------

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
                "User Managed Policy",
                resource,
                document
            )

        # =================================================
        # 2. GROUP POLICIES
        # =================================================

        groups_response = iam.list_groups_for_user(
            UserName=resource
        )

        for group in groups_response["Groups"]:

            group_name = group["GroupName"]

            # =================================================
            # 2A. GROUP INLINE POLICIES
            # =================================================

            group_inline_policies = iam.list_group_policies(
                GroupName=group_name
            )

            for policy_name in group_inline_policies[
                "PolicyNames"
            ]:

                inline_response = iam.get_group_policy(
                    GroupName=group_name,
                    PolicyName=policy_name
                )

                document = inline_response[
                    "PolicyDocument"
                ]

                analyze_policy_document(
                    policy_name,
                    "Group Inline Policy",
                    group_name,
                    document
                )

            # =================================================
            # 2B. GROUP MANAGED POLICIES
            # =================================================

            group_policies = iam.list_attached_group_policies(
                GroupName=group_name
            )

            for policy in group_policies[
                "AttachedPolicies"
            ]:

                policy_name = policy["PolicyName"]

                # -------------------------------------------------
                # AdministratorAccess
                # -------------------------------------------------

                if policy_name == "AdministratorAccess":

                    save_finding(
                        4,
                        "CRITICAL",
                        policy_name,
                        "Group Managed Policy",
                        group_name,
                        (
                            "IAM user receives "
                            "AdministratorAccess through a group"
                        ),
                        (
                            "Follow the principle of least privilege"
                        )
                    )

                    continue

                # -------------------------------------------------
                # Get policy
                # -------------------------------------------------

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
                    version_response[
                        "PolicyVersion"
                    ]["Document"]
                )

                analyze_policy_document(
                    policy_name,
                    "Group Managed Policy",
                    group_name,
                    document
                )

        # =================================================
        # 3. USER INLINE POLICIES
        # =================================================

        inline_policies = iam.list_user_policies(
            UserName=resource
        )

        for policy_name in inline_policies[
            "PolicyNames"
        ]:

            inline_response = iam.get_user_policy(
                UserName=resource,
                PolicyName=policy_name
            )

            document = inline_response[
                "PolicyDocument"
            ]

            analyze_policy_document(
                policy_name,
                "User Inline Policy",
                resource,
                document
            )

        # =================================================
        # 4. SORT FINDINGS BY RISK
        # =================================================

        findings.sort(
            key=lambda finding: finding["score"],
            reverse=True
        )

        # =================================================
        # 5. RETURN FINDINGS
        # =================================================

        if findings:

            highest = findings[0]

            issue_messages = []

            for index, finding in enumerate(
                findings,
                start=1
            ):

                issue_messages.append(
                    (
                        f"{index}. {finding['severity']}\n"
                        f"   Policy      : {finding['policy']}\n"
                        f"   Type        : {finding['policy_type']}\n"
                        f"   Attached To : {finding['attached_to']}\n"
                        f"   Issue       : {finding['message']}"
                    )
                )

            combined_message = (
                f"{len(findings)} IAM security issue(s) detected:\n"
                + "\n\n".join(issue_messages)
            )

            # -------------------------------------------------
            # Remove duplicate recommendations
            # -------------------------------------------------

            recommendations = list(
                dict.fromkeys(
                    finding["recommendation"]
                    for finding in findings
                )
            )

            combined_recommendation = (
                "; ".join(recommendations)
            )

            return Finding(
                service="IAM",
                resource=resource,
                status="FAIL",
                severity=highest["severity"],
                message=combined_message,
                recommendation=combined_recommendation
            )

        # =================================================
        # 6. EVERYTHING LOOKS OK
        # =================================================

        return Finding(
            service="IAM",
            resource=resource,
            status="PASS",
            severity="LOW",
            message=(
                "IAM user permissions do not contain "
                "high-risk wildcard or broad resource patterns"
            ),
            recommendation="No action required"
        )

    # =====================================================
    # ERROR HANDLING
    # =====================================================

    except Exception as e:

        return Finding(
            service="IAM",
            resource=resource,
            status="ERROR",
            severity="HIGH",
            message=(
                f"Unable to check IAM permissions: {str(e)}"
            ),
            recommendation=(
                "Verify AWS IAM permissions"
            )
        )
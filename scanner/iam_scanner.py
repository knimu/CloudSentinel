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
        # DANGEROUS IAM ACTIONS
        # =================================================

        HIGH_RISK_ACTIONS = {
            "iam:CreateUser",
            "iam:CreateAccessKey",
            "iam:AttachUserPolicy",
            "iam:AttachGroupPolicy",
            "iam:AttachRolePolicy",
            "iam:PutUserPolicy",
            "iam:PutGroupPolicy",
            "iam:PutRolePolicy",
            "iam:CreatePolicyVersion",
            "iam:SetDefaultPolicyVersion",
            "iam:PassRole",
            "s3:DeleteBucket",
            "ec2:TerminateInstances"
        }

        MEDIUM_RISK_ACTIONS = {
            "iam:DeleteUser",
            "iam:DeleteAccessKey",
            "iam:DeletePolicy",
            "s3:PutObject",
            "s3:DeleteObject",
            "ec2:StopInstances"
        }

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

            condition_details = []

            for operator, condition_values in condition.items():

                if not isinstance(condition_values, dict):
                    continue

                for key, value in condition_values.items():

                    condition_details.append(
                        f"{operator}: {key} = {value}"
                    )

            if not condition_details:
                return

            # Conditions are informational for now.
            # We do not create a security finding just because
            # a policy contains a condition.

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
            # Normalize actions
            # -------------------------------------------------

            if not isinstance(actions, list):
                actions = [actions]

            actions = [
                action
                for action in actions
                if isinstance(action, str)
            ]

            # -------------------------------------------------
            # Normalize resources
            # -------------------------------------------------

            if not isinstance(resources, list):
                resources = [resources]

            resources = [
                resource
                for resource in resources
                if isinstance(resource, str)
            ]

            # -------------------------------------------------
            # Determine resource scope
            # -------------------------------------------------

            resource_wildcard = "*" in resources

            # -------------------------------------------------
            # Parse scoped resources
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

            # =================================================
            # DAY 11 - DANGEROUS ACTION ANALYSIS
            # =================================================

            dangerous_high = [
                action
                for action in actions
                if action in HIGH_RISK_ACTIONS
            ]

            dangerous_medium = [
                action
                for action in actions
                if action in MEDIUM_RISK_ACTIONS
            ]

            # -------------------------------------------------
            # HIGH-RISK ACTIONS
            # -------------------------------------------------

            if dangerous_high:

                save_finding(
                    4,
                    "CRITICAL",
                    policy_name,
                    policy_type,
                    attached_to,
                    (
                        f'Policy "{policy_name}" allows '
                        f'high-risk action(s): '
                        f'{", ".join(dangerous_high)}'
                    ),
                    (
                        "Review high-risk permissions and "
                        "restrict them to trusted identities "
                        "and required resources"
                    )
                )

                return

            # -------------------------------------------------
            # MEDIUM-RISK ACTIONS
            # -------------------------------------------------

            if dangerous_medium:

                save_finding(
                    2,
                    "MEDIUM",
                    policy_name,
                    policy_type,
                    attached_to,
                    (
                        f'Policy "{policy_name}" allows '
                        f'potentially dangerous action(s): '
                        f'{", ".join(dangerous_medium)}'
                    ),
                    (
                        "Review the permissions and remove "
                        "unnecessary write or destructive actions"
                    )
                )

            # =================================================
            # EXISTING WILDCARD ANALYSIS
            # =================================================

            # -------------------------------------------------
            # CASE 1:
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
            # CASE 2:
            # Service-level wildcard
            #
            # Examples:
            # s3:*
            # iam:*
            # ec2:*
            # -------------------------------------------------

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
            # CASE 3:
            # Broad action wildcard
            #
            # Examples:
            # s3:Get*
            # s3:List*
            # iam:Get*
            # -------------------------------------------------

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
            # CASE 4:
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
            # CASE 5:
            # Scoped resource ARN
            #
            # Example:
            # arn:aws:s3:::bucket-name/*
            #
            # Scoped resources are considered safe for now.
            # -------------------------------------------------

            for parsed in parsed_resources:

                service = parsed["service"]
                resource_name = parsed["resource"]

                # Reserved for future service/resource validation.
                _ = service
                _ = resource_name

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

            if not isinstance(statements, list):
                return

            # -------------------------------------------------
            # Analyze each statement
            # -------------------------------------------------

            for statement in statements:

                if not isinstance(statement, dict):
                    continue

                # -------------------------------------------------
                # We only analyze Allow statements
                # -------------------------------------------------

                if statement.get("Effect") != "Allow":
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

                condition = statement.get(
                    "Condition",
                    {}
                )

                # -------------------------------------------------
                # Analyze condition
                # -------------------------------------------------

                analyze_conditions(
                    policy_name,
                    policy_type,
                    attached_to,
                    condition
                )

                # -------------------------------------------------
                # Analyze actions + resources
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
            # Remove duplicate recommendations while
            # preserving their order
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
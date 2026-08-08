class Finding:
    # creates object and stores the object 
    def __init__(self, service, resource, status, severity, message, recommendation):
        self.service = service
        self.resource = resource
        self.status = status
        self.severity = severity
        self.message = message
        self.recommendation = recommendation
# for printing
# how to display object
    def __str__(self):
        return (
            f"Service: {self.service}\n"
            f"Resource: {self.resource}\n"
            f"Status: {self.status}\n"
            f"Severity: {self.severity}\n"
            f"Message: {self.message}\n"
            f"Recommendation: {self.recommendation}"
        )
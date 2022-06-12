class CustomValidationError(Exception):
    """base class for custom exceptions."""
    pass

class CommitNotFound(CustomValidationError):
    """raised when commmit id is not found in repo"""
    pass

class CurrentCommitExistsError(CustomValidationError):
    """raised when current commit exists in repo. cannot delete current commit"""
    pass

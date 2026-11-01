from __future__ import annotations


class ImprovementError(Exception):
    """Base for improvement-engine errors. Messages are safe by construction
    (fixed text, ids, relative paths); never source dumps, logs or secrets."""


class ImprovementNotFoundError(ImprovementError):
    pass


class InvalidTransitionError(ImprovementError):
    pass


class InvalidProposalError(ImprovementError):
    pass


class PreconditionError(ImprovementError):
    """A lifecycle precondition (validation, approval, state, version) failed."""

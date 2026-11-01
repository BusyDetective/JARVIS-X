class VoiceError(Exception):
    """Base. Messages are safe to show to the user (no audio, no paths)."""


class VoiceDisabledError(VoiceError):
    pass


class VoiceUnavailableError(VoiceError):
    """Provider missing, misconfigured, or runs client-side."""


class SpeechRecognitionError(VoiceError):
    pass


class SpeechSynthesisError(VoiceError):
    pass


class AudioTooLargeError(VoiceError):
    pass

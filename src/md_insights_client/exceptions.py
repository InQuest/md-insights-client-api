"MetaDefender InSights client exceptions"


class ConfigurationError(Exception):
    "Exception indicating a problem with the configuration"


class FeedAccessError(Exception):
    "Exception indicating a problem accessing the feed"


__all__ = ["ConfigurationError", "FeedAccessError"]

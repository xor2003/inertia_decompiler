import warnings


def pytest_configure(config):
    warnings.filterwarnings(
        "ignore",
        message="module 'sre_parse' is deprecated",
        category=DeprecationWarning
    )
    warnings.filterwarnings(
        "ignore",
        message="module 'sre_constants' is deprecated",
        category=DeprecationWarning
    )
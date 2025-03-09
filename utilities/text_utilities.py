import string


def add_trailing_period(sentence):
    """
    Adds a trailing period to the given sentence if it does not already end with punctuation.

    Args:
        sentence (str): The sentence to which a trailing period will be added.

    Returns:
        str: The sentence with a trailing period added if it was missing punctuation.
    """
    if sentence and sentence[-1] not in string.punctuation:
        sentence += '.'
    return sentence


def wrap_prompt_with_delimiters(prompt, delimiter_start, delimiter_end):
    """
    Wraps the given prompt with the specified start and end delimiters.

    Args:
        prompt (str): The prompt to be wrapped.
        delimiter_start (str): The delimiter to be added at the start of the prompt.
        delimiter_end (str): The delimiter to be added at the end of the prompt.

    Returns:
        str: The prompt wrapped with the specified delimiters.
    """
    return f"{delimiter_start}{prompt}{delimiter_end}"

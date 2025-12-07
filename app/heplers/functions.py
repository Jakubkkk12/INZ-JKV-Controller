import re

def check_dict_key(data_dict: dict, key: str) -> bool:
    """
    Checks if a given key exists in a dictionary and handles cases where the
    input 'dict' is not a dictionary (e.g., None).

    Args:
        data_dict (dict): The dictionary to check.
        key (str): The key to look up in the dictionary.

    Returns:
        bool: True if the key exists in the dictionary, False otherwise (including
              if data_dict is None or not a dictionary).
    """
    try:
        data_dict[key]
        return True
    except KeyError:
        return False
    except TypeError:
        return False


def remove_all_key_from_dict(data, key_to_remove):
    """
    Recursively removes all instances of a specified key from a dictionary,
    including keys nested within lists and sub-dictionaries.

    Args:
        data (dict | list | any): The dictionary or list to traverse and modify.
        key_to_remove (str): The key (string) to be removed wherever found.

    Returns:
        dict | list | any: The modified dictionary or list.
    """
    if isinstance(data, dict):
        for key in list(data.keys()):
            if key == key_to_remove:
                del data[key]
            else:
                remove_all_key_from_dict(data[key], key_to_remove)

    elif isinstance(data, list):
        for item in data:
            remove_all_key_from_dict(item, key_to_remove)
    return data


def format_value_error_msg(e: str) -> str:
    start_index = e.find("Value error, ") + len("Value error, ")
    end_index = e.find(" [", start_index)
    return e[start_index:end_index]

import configparser

def create_exclusion_list(entries: list, file_path: str = 'exclusion_list.ini'):
    """Creates an exclusion list in the form of an INI file.
    
    :param entries: A list of entries (e.g., IP addresses) to be excluded.
    :param file_path: Optional file path for saving the exclusion list. Defaults to 'exclusion_list.ini'.
    """
    try:
        config = configparser.ConfigParser()
        config['EXCLUSION_LIST'] = {'Entries': '\n'.join(entries)}

        with open(file_path, 'w') as configfile:
            config.write(configfile)
        
        print(f"Exclusion list created successfully at {file_path}")
    except Exception as e:
        print(f"An error occurred while creating the exclusion list: {e}")

if __name__ == '__main__':
    exclusion_list_entries = [
        # Add the exclusion list entries here
        '127.0.0.1',
        '192.168.1.1',
    ]

    create_exclusion_list(exclusion_list_entries)

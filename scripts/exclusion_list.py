import configparser

def create_exclusion_list(entries: list):
    config = configparser.ConfigParser()
    config['EXCLUSION_LIST'] = {'Entries': '\n'.join(entries)}

    with open('exclusion_list.ini', 'w') as configfile:
        config.write(configfile)

if __name__ == '__main__':
    entries = [
        # Add the exclusion list entries here
        '127.0.0.1',
        '192.168.1.1',
    ]

    create_exclusion_list(entries)

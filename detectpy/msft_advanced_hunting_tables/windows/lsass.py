

def lsass_pshell_get_process(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({kql_ago})
        | where ProcessCommandLine has_all ('Get', 'Process', 'LSASS')
        """
    query_json = {
        "delta": "",
        "title": "Powershell Used Get-Process to Get LSASS Process Id on CommandLine",
        "query": query_text
        }

    return query_json


def lsass_memory_api_call_not_system(kql_ago='1d'):

    query_text = f"""DeviceEvents
        | where Timestamp >= ago({kql_ago})
        | where ActionType =~ 'ReadProcessMemoryApiCall'
            and FileName =~ 'lsass.exe'
            and AccountName !~ 'system'
            and isnotempty(AccountName)
        """
    query_json = {
        "delta": "",
        "title": "LSASS Memory Read from Non-System Account",
        "query": query_text
        }

    return query_json


def lsass_large_memory_api_read_from_rundll(kql_ago='1d'):

    query_text = f"""DeviceEvents
        | where Timestamp >= ago({kql_ago})
        | where ActionType =~ 'ReadProcessMemoryApiCall'
            and FileName =~ 'lsass.exe'
            and InitiatingProcessFileName contains 'rundll'
            and parse_json(AdditionalFields).TotalBytesCopied >= 20000000
        """
    query_json = {
        "delta": "",
        "title": "Large LSASS Memory API Read from Rundll",
        "query": query_text
        }

    return query_json


def lsass_any_memory_api_read_from_rundll(kql_ago='1d'):

    query_text = f"""DeviceEvents
        | where Timestamp >= ago({kql_ago})
        | where ActionType =~ 'ReadProcessMemoryApiCall'
            and FileName =~ 'lsass.exe'
            and InitiatingProcessFileName has_any ('rundll32', 'rundll64')
        """
    query_json = {
        "delta": "",
        "title": "LSASS Any Memory API Read from Rundll",
        "query": query_text
        }

    return query_json


def lsass_any_mem_api_read_and_dump_via_rundll(kql_ago='1d'):

    query_text = f"""DeviceEvents
        | where Timestamp >= ago({kql_ago})
        | where ActionType =~ 'ReadProcessMemoryApiCall'
            and FileName =~ 'lsass.exe'
            and InitiatingProcessFileName has_any ('rundll32', 'rundll64')
        | where InitiatingProcessCommandLine has_any ('#24', '-24', '24', 'minidump', 'minidumpw')
        """
    query_json = {
        "delta": "",
        "title": "LSASS Memory API Read and Dump from Rundll",
        "query": query_text
        }

    return query_json


def lsass_large_memory_api_read_from_taskmgr(kql_ago='1d'):

    query_text = f"""DeviceEvents
        | where Timestamp >= ago({kql_ago})
        | where ActionType =~ 'ReadProcessMemoryApiCall'
            and FileName =~ 'lsass.exe'
            and InitiatingProcessFileName has 'taskmgr'
            and parse_json(AdditionalFields).TotalBytesCopied >= 20000000
        """
    query_json = {
        "delta": "",
        "title": "Large LSASS Memory Read from Taskmgr",
        "query": query_text
        }

    return query_json


def lsass_large_memory_api_read_from_werfault(kql_ago='1d'):

    query_text = f"""DeviceEvents
        | where Timestamp >= ago({kql_ago})
        | where ActionType =~ 'ReadProcessMemoryApiCall'
            and FileName =~ 'lsass.exe'
            and InitiatingProcessFileName has 'werfault'
            and parse_json(AdditionalFields).TotalBytesCopied >= 20000000
        """
    query_json = {
        "delta": "",
        "title": "Large LSASS Memory Read from Werfault",
        "query": query_text
        }

    return query_json


def lsass_named_dump_file_created(kql_ago='1d'):

    query_text = f"""DeviceFileEvents
        | where Timestamp >= ago({kql_ago})
        | where ActionType =~ 'FileCreated'
            and FileName has_all ('lsass', 'dmp')
        """
    query_json = {
        "delta": "",
        "title": "Dump File Created with LSASS in Name",
        "query": query_text
        }

    return query_json


def lsass_shtinkering_silent_process_exit_registry(kql_ago='1d'):

    query_text = f"""DeviceRegistryEvents
        | where Timestamp >= ago({kql_ago})
        | where RegistryKey has_all ('software', 'SilentProcessExit', 'Lsass')
            and RegistryKey has_any ('HKLM', 'HKEY_LOCAL_MACHINE')
        """
    query_json = {
        "delta": "",
        "title": "",
        "query": query_text
        }

    return query_json


def lsass_shtinkering_image_file_(kql_ago='1d'):

    query_text = f"""DeviceRegistryEvents
        | where Timestamp >= ago({kql_ago})
        | where RegistryKey has_all ('software', 'SilentProcessExit', 'Lsass')
            and RegistryKey has_any ('HKLM', 'HKEY_LOCAL_MACHINE')
        """
    query_json = {
        "delta": "",
        "title": "",
        "query": query_text
        }

    return query_json
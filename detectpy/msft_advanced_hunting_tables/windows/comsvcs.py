

def comsvcs_called_minidump_on_cmdline(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({kql_ago})
        | where ProcessCommandLine has_all ('comsvcs', 'minidump')
        """
    query_json = {
        "delta": "comsvcs-p0001--proces-create-windows",
        "title": "Comsvcs.dll Called MiniDump on CommandLine",
        "query": query_text
        }

    return query_json


def comsvcs_called_minidumpw_function_on_cmdline(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({kql_ago})
        | where ProcessCommandLine has_all ('comsvcs', '#24')
            or ProcessCommandLine has_all ('comsvcs', '-24')
        """
    query_json = {
        "delta": "comsvcs-p0002--proces-create-windows",
        "title": "Comsvcs.dll Called MiniDumpW Function on CommandLine",
        "query": query_text
        }

    return query_json


def comsvcs_created_file(kql_ago='1d'):

    query_text = f"""DeviceFileEvents
        | where Timestamp >= ago({kql_ago})
        | where ActionType =~ 'FileCreated'
            and InitiatingProcessCommandLine has 'comsvcs'
        """
    query_json = {
        "delta": "comsvcs-p0003--file-create-windows",
        "title": "Comsvcs.dll Used to Create File",
        "query": query_text
        }
    return query_json


def comsvcs_process_dump_on_cmdline(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({kql_ago})
        | where ProcessCommandLine has 'comsvcs'
            and ProcessCommandLine has_any ('#24', '-24', 'minidump', 'minidumpw', '24')
        """
    query_json = {
        "delta": [
            "comsvcs-p0002--process-create-windows",
            "comsvcs-p0001--process-create-windows"],
        "title": "Comsvcs.dll Process Dump on Command Line",
        "query": query_text
        }

    return query_json


def comsvcs_lsass_read_minidump(kql_ago='1d'):

    query_text = f"""DeviceEvents
        | where Timestamp >= ago({kql_ago})
        | where ActionType =~ 'ReadProcessMemoryApiCall'
            and FileName =~ 'lsass.exe'
            and InitiatingProcessCommandLine has_all ('comsvcs', 'minidump')
        """
    query_json = {
        "delta": "",
        "title": "Comsvcs Accessed LSASS via Rundll and ReadProcessApiCall Data and Dumped Memory with MiniDump",
        "query": query_text
        }

    return query_json


def comsvcs_lsass_read_minidumpw(kql_ago='1d'):

    query_text = f"""DeviceEvents
        | where Timestamp >= ago({kql_ago})
        | where ActionType =~ 'ReadProcessMemoryApiCall'
            and FileName =~ 'lsass.exe'
            and InitiatingProcessCommandLine has 'comsvcs'
        | where InitiatingProcessCommandLine has_any ('#24', '-24', '24')
        """
    query_json = {
        "delta": "",
        "title": "Comsvcs Accessed LSASS via Rundll in ReadProcessApiCall Data and Dumped Memory with MiniDumpW",
        "query": query_text
        }

    return query_json


def comsvcs_lsass_read_memory_dump(kql_ago='1d'):

    query_text = f"""DeviceEvents
        | where Timestamp >= ago({kql_ago})
        | where ActionType =~ 'ReadProcessMemoryApiCall'
            and FileName =~ 'lsass.exe'
            and InitiatingProcessCommandLine has 'comsvcs'
        | where InitiatingProcessCommandLine has_any ('#24', '-24', '24', 'minidump', 'minidumpw')
        """
    query_json = {
        "delta": "",
        "title": "Comsvcs Accessed LSASS via Rundll in ReadProcessApiCall Data and Dumped Memory",
        "query": query_text
        }

    return query_json





def comsvcs_called_minidump_on_cmdline(self, kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({kql_ago})
        | where ProcessCommandLine has_all ('comsvcs', 'minidump')
        """
    query_json = {
        "delta": "comsvcs-p0001",
        "title": "Comsvcs.dll Called MiniDump on CommandLine",
        "query": self.query_text
        }

    return query_json


def comsvcs_called_minidumpw_function_on_cmdline(self, kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({kql_ago})
        | where ProcessCommandLine has_all ('comsvcs', '#24')
            or ProcessCommandLine has_all ('comsvcs', '-24')
        """
    query_json = {
        "delta": "comsvcs-p0002",
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
        "delta": "comsvcs-p0003",
        "title": "Comsvcs.dll Used to Create File",
        "query": query_text
        }
    return query_json


def comsvcs_suspicious_minidump_on_cmdline(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({kql_ago})
        | where ProcessCommandLine has 'comsvcs'
            and ProcessCommandLine has_any ('#24', '-24', 'minidump', 'minidumpw')
        """
    query_json = {
        "delta": [
            "comsvcs-p0002",
            "comsvcs-p0001"],
        "title": "Comsvcs.dll Suspicous Minidump on Command Line",
        "query": query_text
        }

    return query_json




class Comsvcs:

    def __init__(self):
        self.kql_ago = None
        self.query_json = None
        self.query_text = None


    def comsvcs_p0001(self, kql_ago='1d'):

        self.query_text = f"""DeviceProcessEvents
            | where Timestamp >= ago({kql_ago})
            | where ProcessCommandLine has_all ('comsvcs', 'minidump')
            """
        self.query_json = {"delta": "comsvcs-p0001",
                           "title": "Comsvcs.dll Called MiniDump on CommandLine",
                           "query": self.query_text
        }

        return self


    def comsvcs_p0002(self, kql_ago='1d'):

        self.query_text = f"""DeviceProcessEvents
            | where Timestamp >= ago({kql_ago})
            | where ProcessCommandLine has_all ('comsvcs', '#24')
                or ProcessCommandLine has_all ('comsvcs', '-24')
            """
        self.query_json = {"delta": "comsvcs-p0002",
                           "title": "Comsvcs.dll Called MiniDumpW Function on CommandLine",
                           "query": self.query_text
        }

        return self


    def comsvcs_p0003(self, kql_ago='1d'):

        self.query_text = f"""DeviceFileEvents
            | where Timestamp >= ago({kql_ago})
            | where ActionType =~ 'FileCreated'
                and InitiatingProcessCommandLine has 'comsvcs'
            """
        self.query_json = {"delta": "comsvcs-p0003",
                           "title": "Comsvcs.dll Used to Create File",
                           "query": self.query_text
        }
        return self


class WAF (object):
    def __init__(self):
        self.req_headers = None
        self.violation_details = None

    @staticmethod
    def filter_example(events):
        """
        Do nothing.
        Target: apply a filter
        :return:
        """
        return events


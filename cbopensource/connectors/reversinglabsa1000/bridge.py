from cbint.utils.detonation import DetonationDaemon
from cbint.utils.detonation.binary_analysis import (BinaryAnalysisProvider, AnalysisInProgress, AnalysisResult,
                                                    AnalysisTemporaryError, AnalysisPermanentError)
from cbint.utils import feed

from cbapi.connection import CbAPISessionAdapter

from rl_apiclient import (ReversingLabsAnalysisClient, RLAPIQUOTAREACHED)

from datetime import (datetime, timedelta)
from urlparse import urljoin

from requests import Session

import logging

log = logging.getLogger(__name__)


SEVERITY = {
    0: 0,
    1: 20,
    2: 40,
    3: 60,
    4: 80,
    5: 100
}


class ReversingLabsA1000Provider(BinaryAnalysisProvider):

    def __init__(self, name, api_token=None, url=None, days_rescan=None, log_level=None, submit_full_binaries=None):
        super(ReversingLabsA1000Provider, self).__init__(name)

        session = Session()
        tls_adapter = CbAPISessionAdapter(force_tls_1_2=True)
        session.mount("https://", tls_adapter)
        self.base_url = url
        self.rl_analysis = ReversingLabsAnalysisClient(session=session,
                                                       api_token=api_token,
                                                       base_url=url,
                                                       log_level=log_level)

        self.submit_full_binaries = submit_full_binaries

        if int(days_rescan) > 0 and 'NEVER' not in days_rescan.upper():
            self.days_rescan = int(days_rescan)
        else:
            self.days_rescan = None

    def make_result(self, md5sum=None, result=None):

        try:
            result = self.rl_analysis.get_report(md5sum) if not result else result
        except Exception as err:
            raise AnalysisTemporaryError(message="API error: %s" % str(err), retry_in=360)

        if result.get('code'):
            raise AnalysisTemporaryError(
                message='No results on A1000. Allow submit_full_binaries to get results on A1000',
                retry_in=15*60)

        log.info("Result for md5: %s" % md5sum)
        result_link = urljoin(self.base_url, md5sum)
        threat_score = int(result.get("threat_level"))
        trust_factor = int(result.get("trust_factor"))
        threat_name = result.get("treat_name")

        score = SEVERITY[threat_score]
        status = result.get("threat_status").upper()

        if 'UNKNOWN' in status:
            malware_result = """ReversingLabs report for md5: %s
                                Status: %s""" % (md5sum, status)

            report_string = """Report string (test string)"""
            return AnalysisResult(message=malware_result,
                                  extended_message=report_string,
                                  link=result_link,
                                  score=0)

        malware_result = """"ReversingLabs report for md5: %s.
        Status: %s
        Threat name: %s
        Threat score: %s
        Trust factor: %s""" % (md5sum, status, threat_name, threat_score, trust_factor)

        report_string = """Report string (test string)"""
        return AnalysisResult(message=malware_result,
                              extended_message=report_string,
                              link=result_link,
                              score=score)

    def check_result_for(self, md5sum):

        log.info("Submitting hash %s to RL for analysis" % md5sum)
        try:
            response = self.rl_analysis.get_report(resource_hash=md5sum)
        except RLAPIQUOTAREACHED as rle:
            log.info(rle)
            raise AnalysisTemporaryError(message="Quota reached. Will retry in 30 min", retry_in=30 * 60)
        except Exception as err:
            log.info(err)
            raise AnalysisTemporaryError(message="There was an error. Error: {}".format(str(err)), retry_in=60 * 60)

        if response.get('code'):
            raise AnalysisTemporaryError(
                message='No results on A1000. Allow submit_full_binaries to get results on A1000',
                retry_in=30*60)

        return self.make_result(md5sum=md5sum, result=response)

    def analyze_binary(self, md5sum, binary_file_stream):

        if not self.submit_full_binaries:
            raise AnalysisPermanentError(message="NOT SUBMITTING FULL BINARIES")

        log.info("Submitting FULL binary %s to ReversingLabs for analysis" % md5sum)

        try:
            response = self.rl_analysis.submit_file(resource_hash=md5sum, stream=binary_file_stream)
        except RLAPIQUOTAREACHED:
            raise AnalysisTemporaryError(message="RLAPIQUOTAREACHED", retry_in=15*60)

        if response.status_code == 200 or response.status_code == 201:
            return self.check_result_for(md5sum=md5sum)
        else:
            raise AnalysisTemporaryError(message="Unknown error: %s" % str(response), retry_in=15*60)


class ReversingLabsA1000Connector(DetonationDaemon):
    @property
    def filter_spec(self):
        filters = []
        max_module_len = 10 * 1024 * 1024
        filters.append('orig_mod_len:[1 TO {}]'.format(max_module_len))
        additional_filter_requirements = self.get_config_string("binary_filter_query", None)
        if additional_filter_requirements:
            filters.append(additional_filter_requirements)

        return " ".join(filters)

    @property
    def integration_name(self):
        return 'Cb ReversingLabs connector 1.0'

    @property
    def num_quick_scan_threads(self):
        return self.get_config_integer("reversinglabs_quick_scan_threads", 2)

    @property
    def num_deep_scan_threads(self):
        return self.get_config_integer("reversinglabs_deep_scan_threads", 0)

    def get_provider(self):
        reversinglabs_provider = ReversingLabsA1000Provider(name=self.name,
                                                       api_token=self.api_token,
                                                       days_rescan=self.days_rescan,
                                                       url=self.reversinglabs_api_url,
                                                       log_level=self.log_level,
                                                       submit_full_binaries=self.submit_full_binaries)

        return reversinglabs_provider

    def get_metadata(self):
        return feed.generate_feed(self.name,
                                  summary="ReversingLabs is the industry's leading static file analysis platform, providing access to the industry's largest private collection of file reputation data with over 7 billion malware and goodware samples.  ReversingLabs File Reputation classifies file samples and enriches threat intelligence provided by Carbon Black.  The ReversingLabs A1000 malware analysis workstation integration with Carbon Black provides pivots for hunting and investigation by SOC/Analyst teams with YARA-based rules matching.",
                                  tech_data="A ReversingLabs private API key is required to use this feed. There are no requirements to share any data with Carbon Black or ReversingLabs to use this feed. However, binaries may be shared with ReversingLabs.",
                                  provider_url="https://www.reversinglabs.com/",
                                  icon_path="/usr/share/cb/integrations/reversinglabs-a1000/cb-a1000.png",
                                  display_name="ReversingLabs - A1000",
                                  category="Connector")

    def validate_config(self):
        super(ReversingLabsA1000Connector, self).validate_config()

        # check configuration options
        self.check_required_options(["reversinglabs_api_token"])
        self.api_token = self.get_config_string("reversinglabs_api_token", None)
        self.reversinglabs_api_url = self.get_config_string("reversinglabs_api_host", None)
        self.days_rescan = self.get_config_string("days_rescan", None)

        # check submit binaries option
        self.submit_full_binaries = self.get_config_string("submit_full_binaries", '0')
        self.submit_full_binaries = True if self.submit_full_binaries.lower() in ['true', '1'] else False

        # log warning if submit binaries
        if self.submit_full_binaries and self.num_deep_scan_threads > 0:
            log.info("WARNING: This connector is currently configured to sumbit FULL binaries to ReversingLabs")
            log.info("WARNING: If this is not your intention please modify connector.conf")
            log.info("WARNING: Set submit_full_binaries = 0 and reversinglabs_deep_scan_threads = 0")

        # check log level options
        self.log_level = self.get_config_string("debug", 0)
        self.log_level = logging.DEBUG if int(self.log_level) is 1 else logging.INFO

        # set log level
        log.setLevel(self.log_level)
        return True


if __name__ == "__main__":
    import os

    my__path = os.path.dirname(os.path.abspath(__file__))
    temp_directory = "/tmp/reversinglabs"

    config_path = os.path.join(my__path, "testing.conf")
    deamon = ReversingLabsA1000Connector(name="reversinglabsa1000",
                                    configfile=config_path,
                                    work_directory=temp_directory,
                                    logfile=os.path.join(temp_directory, 'test.log'),
                                    debug=True)

    logging.getLogger().setLevel(logging.DEBUG)

    deamon.start()

import logging
import os

from urlparse import urljoin

log = logging.getLogger(__name__)


class RLAPIQUOTAREACHED(Exception):
    pass


class ReversingLabsAnalysisClient(object):

    def __init__(self, session=None, api_token=None, base_url=None, log_level=None):

        self.session = session
        self.api_token = api_token if api_token else None

        self.base_url = base_url if base_url else "http://a1000-dev.rl.lan/"
        if log_level:
            log.setLevel(logging.DEBUG)
        else:
            log.setLevel(logging.INFO)

    def submit_file(self, resource_hash=None, stream=None):
        # create request url to upload files to A1000
        file_upload_url = '/api/uploads/'
        request_url = urljoin(self.base_url, file_upload_url)

        log.info("RL Analysis: submit_file: hash = %s " % (resource_hash))

        file_name = None
        if hasattr(stream, "name"):
            log.info("submitting file: fs.name: %s" % stream.name)
            file_name = os.path.basename(stream.name)

        header = {"Authorization": "Token %s" % self.api_token}
        files = {"file": (file_name, open(file_name, 'rb'))} if file_name else {"file": (resource_hash, stream)}

        data = {
            "analysis": "cloud",
            "tags": "cb",
            "comment": "Uploaded with cb connector"
        }
        response = self.session.post(request_url, files=files, headers=header, data=data, verify=False)
        log.debug("submit_file: response = %s" % response.json())

        if response.status_code == 403:
            raise RLAPIQUOTAREACHED()

        return response

    def rescan_hash(self, resource_hash):
        # create request url to rescan sample hash
        analyze_sample_url = '/api/samples/%s/analyze/' % resource_hash
        request_url = urljoin(self.base_url, analyze_sample_url)

        log.info("rescan_hash: resource_hash = %s" % resource_hash)
        header = {"Authorization": "Token %s" % self.api_token}
        data = {'analysis': 'cloud'}

        # check if hash is not empty
        if not resource_hash:
            raise Exception("No resources provided")

        # create request
        response = self.session.post(request_url, headers=header, data=data, verify=False)

        log.debug("Rescan hash: response = %s" % response)
        if response.status_code == 403:
            raise RLAPIQUOTAREACHED()

        return response.json()

    def get_report(self, resource_hash=None):
        # create request url to get feed result from ticloud
        feed_request_url = '/api/samples/%s/' % resource_hash
        request_url = urljoin(self.base_url, feed_request_url)

        log.info("get_report: resource_hash = %s" % resource_hash)

        # auth data and params
        header = {"Authorization": "Token %s" % self.api_token}
        data = {"analysis": "cloud"}

        if not resource_hash:
            raise Exception("No hash provided")

        response = self.session.get(request_url, headers=header, data=data, verify=False)

        if response.status_code == 403:
            raise RLAPIQUOTAREACHED()

        return response.json()


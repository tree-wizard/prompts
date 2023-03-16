# Base Prompt:

# write python fuzz tests using atheris library
# https://github.com/google/atheris
"""
# Generic Atheris fuzz Example
# !/usr/bin/python3
import atheris
with atheris.instrument_imports():
  import some_library
  import sys

def TestOneInput(data):
  some_library.parse(data)
atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()

# When fuzzing Python, Atheris will report a failure if the Python code under test throws an uncaught exception.
"""
# Atheris FuzzedDataProvider API Reference
# Often, a bytes object is not convenient input to your code being fuzzed. Similar to libFuzzer,
# we provide a FuzzedDataProvider to translate these bytes into other input forms.
# To construct the FuzzedDataProvider, use the following code:
# fdp = atheris.FuzzedDataProvider(input_bytes)
#The FuzzedDataProvider provides the following functions:
# ConsumeBytes(count: int): Consume count bytes.
# ConsumeUnicode(count: int): Consume unicode characters. Might contain surrogate pair characters, which according to the specification are invalid in this situation. However, many core software tools (e.g. Windows file paths) support them, so other software often needs to too.
# ConsumeUnicodeNoSurrogates(count: int): Consume unicode characters, but never generate surrogate pair characters.
# ConsumeString(count: int): Alias for ConsumeBytes in Python 2, or ConsumeUnicode in Python 3.
# ConsumeInt(int: bytes): Consume a signed integer of the specified size (when written in two's complement notation).
# ConsumeUInt(int: bytes): Consume an unsigned integer of the specified size.
# ConsumeIntInRange(min: int, max: int): Consume an integer in the range [min, max].
# ConsumeIntList(count: int, bytes: int): Consume a list of count integers of size bytes.
# ConsumeIntListInRange(count: int, min: int, max: int): Consume a list of count integers in the range [min, max].
# ConsumeFloat(): Consume an arbitrary floating#point value. Might produce weird values like NaN and Inf.
# ConsumeRegularFloat(): Consume an arbitrary numeric floating#point value; never produces a special type like NaN or Inf.
# ConsumeProbability(): Consume a floating#point value in the range [0, 1].
# ConsumeFloatInRange(min: float, max: float): Consume a floating#point value in the range [min, max].
# ConsumeFloatList(count: int): Consume a list of count arbitrary floating#point values. Might produce weird values like NaN and Inf.
# ConsumeRegularFloatList(count: int): Consume a list of count arbitrary numeric floating#point values; never produces special types like NaN or Inf.
# ConsumeProbabilityList(count: int): Consume a list of count floats in the range [0, 1].
# ConsumeFloatListInRange(count: int, min: float, max: float): Consume a list of count floats in the range [min, max].
# PickValueInList(l: list): Given a list, pick a random value.
# ConsumeBool(): Consume either True or False.


## Examples:

# Function signature is zlib.decompress(data, /, wbits=MAX_WBITS, bufsize=DEF_BUF_SIZE)
# https://docs.python.org/3/library/zlib.html
# fuzz test for zlib.decompress():
"""
# An example of fuzzing with a custom mutator in Python.
import atheris

with atheris.instrument_imports():
  import sys
  import zlib


def CustomMutator(data, max_size, seed):
  try:
    decompressed = zlib.decompress(data)
  except zlib.error:
    decompressed = b'Hi'
  else:
    decompressed = atheris.Mutate(decompressed, len(decompressed))
  return zlib.compress(decompressed)

@atheris.instrument_func  # Instrument the TestOneInput function itself
def TestOneInput(data):

#The entry point for our fuzzer.
#  This is a callback that will be repeatedly invoked with different arguments
#  after Fuzz() is called.
#  We translate the arbitrary byte string into a format our function being fuzzed
#  can understand, then call it.
#  Args:
#    data: Bytestring coming from the fuzzing engine.

  try:
    decompressed = zlib.decompress(data)
  except zlib.error:
    return

  if len(decompressed) < 2:
    return
  try:
    if decompressed.decode() == 'FU':
      raise RuntimeError('Boom')
  except UnicodeDecodeError:
    pass

if __name__ == '__main__':
  if len(sys.argv) > 1 and sys.argv[1] == '--no_mutator':
    atheris.Setup(sys.argv, TestOneInput)
  else:
    atheris.Setup(sys.argv, TestOneInput, custom_mutator=CustomMutator)
  atheris.Fuzz()
  """


# function signature is np.loadtxt(fname, dtype=<class 'float'>, comments='#', delimiter=None, converters=None, skiprows=0, usecols=None, unpack=False, ndmin=0, encoding='bytes', max_rows=None, *, quotechar=None, like=None)
# https://numpy.org/doc/stable/reference/generated/numpy.loadtxt.html
#fuzz test for np.loadtxt():
"""
import atheris
import sys

with atheris.instrument_imports():
  from io import StringIO
  import numpy as np

def get_fuzz_types():
    # Define the rows
    dtype = np.dtype(
        [('f0', np.uint16), ('f1', np.float64), ('f2', 'S7'), ('f3', np.int8)]
    )

    # An expected match
    expected = np.array(
        [
            (1, 2.4, "a", -34),
            (2, 3.1, "b", 29),
            (3, 9.9, "g", 120),
        ],
        dtype=dtype
    )
    return dtype, expected

def TestOneInput(fuzz_data):
  dtype, expected = get_fuzz_types()
  fdp = atheris.FuzzedDataProvider(fuzz_data)
  new_data = StringIO(fdp.ConsumeString(sys.maxsize))
  try:
    np.loadtxt(new_data, dtype=dtype, delimiter=";", skiprows=True)
  # Catch all of the exceptions that are caught in 
  # https://github.com/numpy/numpy/blob/main/numpy/lib/tests/test_loadtxt.py
  except StopIteration:
    return
  except ValueError:
    return
  except IndexError:
    return
  except TypeError:
    return
  except RuntimeError:
    return

def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()

if __name__ == "__main__":
  main()
  """

# https://urllib3.readthedocs.io/en/stable/reference/urllib3.poolmanager.html
# fuzz test for urllib3.PoolManager(request):
"""
import atheris
from http.server import BaseHTTPRequestHandler, HTTPServer
import sys
import threading
import time

with atheris.instrument_imports():
    import urllib3

timeout = urllib3.util.Timeout(connect=1.0, read=1.0)
urllib_pool = urllib3.PoolManager(timeout=timeout)

PORT = 8011
GLOBAL_RESPONSE_MESSAGE = ""
GLOBAL_RESPONSE_CODE = 0
GLOBAL_CONTENT_ENCODING = None


class handler(BaseHTTPRequestHandler):
    def send_fuzzed_response(self):
        self.send_response(GLOBAL_RESPONSE_CODE)
        self.send_header("content-type", "text/html")
        if GLOBAL_CONTENT_ENCODING:
            self.send_header("content-encoding", GLOBAL_CONTENT_ENCODING)
        self.end_headers()

        self.wfile.write(bytes(GLOBAL_RESPONSE_MESSAGE, "utf-8"))

    def do_GET(self):
        self.send_fuzzed_response()
    def do_POST(self):
        self.send_fuzzed_response()
    def do_PUT(self):
        self.send_fuzzed_response()
    def do_PATCH(self):
        self.send_fuzzed_response()
    def do_OPTIONS(self):
        self.send_fuzzed_response()
    def do_DELETE(self):
        self.send_fuzzed_response()
    def do_HEAD(self):
        self.send_fuzzed_response()
    # Supress HTTP log output
    def log_request(self, code="-", size="-"):
        return

def run_webserver():
    with HTTPServer(("", PORT), handler) as server:
        server.serve_forever()

REQUEST_METHODS = ["POST", "GET", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"]
CONTENT_ENCODING_TYPES = [None, "gzip", "deflate"]

def TestOneInput(input_bytes):
    global GLOBAL_RESPONSE_MESSAGE, GLOBAL_RESPONSE_CODE, GLOBAL_CONTENT_ENCODING
    fdp = atheris.FuzzedDataProvider(input_bytes)

    # Fuzz Http Response
    GLOBAL_RESPONSE_MESSAGE = fdp.ConsumeUnicodeNoSurrogates(sys.maxsize)
    GLOBAL_RESPONSE_CODE = fdp.ConsumeIntInRange(200, 599)
    GLOBAL_CONTENT_ENCODING = fdp.PickValueInList(CONTENT_ENCODING_TYPES)

    # Fuzz Http Request
    requestType = fdp.PickValueInList(REQUEST_METHODS)
    # Optionally provide request headers
    requestHeaders = urllib3._collections.HTTPHeaderDict({})
    for i in range(0, fdp.ConsumeIntInRange(0, 10)):
        requestHeaders.add(
            fdp.ConsumeString(sys.maxsize), fdp.ConsumeString(sys.maxsize)
        )
    requestHeaders = None if fdp.ConsumeBool() else requestHeaders

    # Optionally generate form data for request
    formData = {}
    for i in range(0, fdp.ConsumeIntInRange(0, 100)):
        formData[fdp.ConsumeString(sys.maxsize)] = fdp.ConsumeString(sys.maxsize)
    formData = None if fdp.ConsumeBool() else formData

    # Optionally generate request body
    requestBody = None if fdp.ConsumeBool() else fdp.ConsumeString(sys.maxsize)

    r = urllib_pool.request(
        requestType,
        f"http://localhost:{PORT}/",
        headers=requestHeaders,
        fields=formData,
        body=requestBody
    )
    r.status
    r.data
    r.headers

if __name__ == "__main__":
    x = threading.Thread(target=run_webserver, daemon=True)
    x.start()

    time.sleep(0.5)  # Short delay to start test server
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
"""


# function signature is urllib.util.parse_url(str)
# https://urllib3.readthedocs.io/en/stable/reference/urllib3.util.html#urllib3.util.parse_url
# fuzz test for  urllib3.util.parse_url().
"""
import os
import sys
import atheris
import urllib3

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    original = fdp.ConsumeUnicode(sys.maxsize)

    try:
        response = urllib3.util.parse_url(original)
        response.hostname
        response.request_uri
        response.authority
        response.netloc
        response.url
    except urllib3.exceptions.LocationParseError:
        None
    return

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    atheris.instrument_all()
    main()
"""

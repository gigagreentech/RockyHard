#!/usr/bin/env python

import sys, getopt, os, errno, json, syslog, tempfile

def usage():
    print ("""Usage: %s
    Performs onboarding or offboarding to WDATP locally
""" % sys.argv[0])
    pass

def create_dir(directory_path):
    if not os.path.exists(directory_path):
        os.makedirs(directory_path) 

try:
    opts, args = getopt.getopt(sys.argv[1:], 'hc', ['help', 'config='])

    for k, v in opts:
        if k == '-h' or k == '--help':
            usage()
            sys.exit(0)

except getopt.GetoptError as e:
    print (e)
    print ('')
    usage()
    sys.exit(2)

try:
    destfile = '/etc/opt/microsoft/mdatp/mdatp_onboard.json'

    if os.geteuid() != 0:
        print('Re-running as sudo (you may be required to enter sudo''s password)')
        os.execvp('sudo', ['sudo', 'python'] + sys.argv)  # final version

    print('Generating %s ...' % destfile)

    create_dir(os.path.dirname(destfile))

    with open(destfile, "w") as json_file:
        json_file.write('''{
  "onboardingInfo": "{\\\"body\\\":\\\"{\\\\\\\"previousOrgIds\\\\\\\":[],\\\\\\\"orgId\\\\\\\":\\\\\\\"5e6016a0-af89-44e6-a60d-b3b83956e430\\\\\\\",\\\\\\\"geoLocationUrl\\\\\\\":\\\\\\\"https://winatp-gw-usgt.microsoft.com/\\\\\\\",\\\\\\\"datacenter\\\\\\\":\\\\\\\"UsGovTexas\\\\\\\",\\\\\\\"vortexGeoLocation\\\\\\\":\\\\\\\"FFL4\\\\\\\",\\\\\\\"version\\\\\\\":\\\\\\\"2.12\\\\\\\",\\\\\\\"deviceType\\\\\\\":\\\\\\\"Server\\\\\\\",\\\\\\\"packageGuid\\\\\\\":\\\\\\\"0ca2c9be-6982-43d6-b940-cf42bc04d846\\\\\\\"}\\\",\\\"sig\\\":\\\"38DOhbncYSTtMgfvFpD2hMsR4ErtbwtgsrFpcCaCe4mOXv++P/+RF6DtmfMitrMHH8giYmuhRFzU+Wd5s4jIUv2yUkNXrzUmm52vrOXyQHfpfa0LHXrr49qtZ4016SxfewWTjfPWoUNg2hvdOrDgcKCZ3uJGcNObG6x7Kg44yg8n/V9lBXGH59CZ2Y79FDrPcnvKrYNKQOcVAS8gmilK1lzVO5d2uTicEFNm7pYXPEBHzKXzjxejZwPsA+5iL57zgSDyYnS50yU6FJMmh6mVC54DPNOw6r7NwIz2G9CdhO5gGm0E/Vafeg/ojfEV46beX8wlgFBCsoLt6zpYEEguoA==\\\",\\\"sha256sig\\\":\\\"38DOhbncYSTtMgfvFpD2hMsR4ErtbwtgsrFpcCaCe4mOXv++P/+RF6DtmfMitrMHH8giYmuhRFzU+Wd5s4jIUv2yUkNXrzUmm52vrOXyQHfpfa0LHXrr49qtZ4016SxfewWTjfPWoUNg2hvdOrDgcKCZ3uJGcNObG6x7Kg44yg8n/V9lBXGH59CZ2Y79FDrPcnvKrYNKQOcVAS8gmilK1lzVO5d2uTicEFNm7pYXPEBHzKXzjxejZwPsA+5iL57zgSDyYnS50yU6FJMmh6mVC54DPNOw6r7NwIz2G9CdhO5gGm0E/Vafeg/ojfEV46beX8wlgFBCsoLt6zpYEEguoA==\\\",\\\"cert\\\":\\\"MIIFwjCCA6qgAwIBAgITMwAABCKNuvsKs/9IHgAAAAAEIjANBgkqhkiG9w0BAQsFADB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQgU2VjdXJlIFNlcnZlciBDQSAyMDExMB4XDTI1MTIxMTE5MTkxM1oXDTI2MTAxNzE5MTkxM1owQjFAMD4GA1UEAxM3bTM2NWRvb3AtQ2xvdWRDbGllbnRBdXRoZW50aWNhdGlvbi1GRi51c2dvdmNsb3VkYXBwLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANmeI1JyYIgu23GwnewOIQk0HTlsnAyfI4A41nz08Hkwrdu6c4X2bFxDpaBvIt3C0XVC8br23tm/3TXHl/wqUb6zo6WZuzDM1aiJFs+Vl2p7dAwcUg6U5JLwUR+fJrg4mHHgPbpZIO+cE61fj8/Ehjm7xFJL+8/0TDWQGbILlTxjz85gX0210k1+YpFWF62ytOw67SIMEBKJx9QsTCwvDzliH8M1hRntlQ9dRGCyeT+LXxq2sE0z4Rm/x4Xm3TKGXlGntaqc5YlI5sP8IchI2sIdtuk68qJJaAdMhwPOKhG3MeXnO3mF29oHaJ1KE2Atq06752OVHl2jLWekcpUynnUCAwEAAaOCAXMwggFvMA4GA1UdDwEB/wQEAwIFIDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADA5BgNVHREEMjAwgi5DbG91ZENsaWVudEF1dGhlbnRpY2F0aW9uLUZGLnVzZ292Y2xvdWRhcHAubmV0MB0GA1UdDgQWBBRfKJ7dJGpMz9JOvMs8flcQJXH0HDAfBgNVHSMEGDAWgBQ2VollSctbmy88rEIWUE2RuTPXkTBTBgNVHR8ETDBKMEigRqBEhkJodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNTZWNTZXJDQTIwMTFfMjAxMS0xMC0xOC5jcmwwYAYIKwYBBQUHAQEEVDBSMFAGCCsGAQUFBzAChkRodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY1NlY1NlckNBMjAxMV8yMDExLTEwLTE4LmNydDANBgkqhkiG9w0BAQsFAAOCAgEAage91HAI1fcOoeeYFiiVGzBEarrbXDjA1FoJc7wC7eWGaLoUco39oSAXklO3VbUIRUeXTGL7YX50BdFRCdl05kFhR3wIAfAspDDPkwYa3phbiaFMsdwgcJNWODYvY0J8ZqvEnEOQMcC2+erd1/Q3JOitctLBBhFJRIj+3ybq6K623pVjH41tvZVYmt37bTGPmyI6sfPDS+un0VP5Au1NtmiDNJXIPerpeOeYByG6PF9Fojvy7ozVk2sgsrIdlcTAUs4BiWqTZoki9SVfS5Z2NFvjw4SoxkDRxKMA/UwAEk9kYLHRD0NnhocVHF+N2Oz80l4UrKR+dC2L/2olvcwlLykXHuWRQzh23FyGrhIDJtCOfHLm/QjIxkJp5cNp6gP71Eqa9TamawBlocrj1xgo3opZC7dPydFl9Ui5KM7cNzvu3I0zNXvd7/NO4JZgXw6rZpkJfzNi45k2w3U0yls/05fC8Q7DrR/UDLpOcW9ecicJ5yEs1+KEyQ/N/yVx1xP2ccmh46vCZ4uniN5y/E92TNOYxe6XDOd5xd4grDX5P1X3CmRm87W3+iH3d3JVgf2RjWtyc6endCY+csWhqq3FopsNYeKPHM7PSBOPFC5lXV0Q7yaH1rqeLMvQUHE+ZhkpjHg3xFYqpfuU4U+IepPVBoXtraF5A75s7SORYaGNvXk=\\\",\\\"chain\\\":[\\\"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\\\"]}"
}''')

    os.chmod(destfile, 0o640)

    syslog.syslog(syslog.LOG_WARNING, "Microsoft ATP: succeeded to save json file %s." % (destfile))

except Exception as e:
    print(str(e))
    syslog.syslog(syslog.LOG_ERR, "Microsoft ATP: failed to save json file %s. Exception occured: %s." % (destfile, str(e)))
    sys.exit(1)
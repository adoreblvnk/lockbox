# Edwin Code

# Edwins Code

import re
import os
from unicodedata import name
from Processor import KeywordProcessor

class PrivacyFilter:
    def __init__(self):
        self.keyword_processor = KeywordProcessor(case_sensitive=False)
        self.keyword_processor_names = KeywordProcessor(case_sensitive=False)
        self.initialised = False
        self.use_wordlist = True
        self.use_re = True
        ##### CONSTANTS #####
        self._punctuation = ['.', ',', ' ', ':', ';', '?', '!']

    def file_to_list(self, filename):
        items_count = 0
        items = []

        with open(filename, "r", encoding="utf-8") as f:
            for line in f.readlines():
                items_count += 1
                line = line.rstrip()
                items.append(line)

        return items

    def initialize(self, wordlist_filter=True,
                   regular_expressions=True, fields=None):
        if not fields:
            fields = {
                os.path.join('datasets', 'firstnames.csv'): {"replacement": "<NAME>",
                                                             "punctuation": self._punctuation},
                os.path.join('datasets', 'lastnames.csv'): {"replacement": "<NAME>",
                                                            "punctuation": self._punctuation},
                os.path.join('datasets', 'streets.csv'): {"replacement": "<STREETS>", "punctuation": self._punctuation},
                os.path.join('datasets', 'nationalities.csv'): {"replacement": "<NATIONALITIES>", "punctuation": None},
                os.path.join('datasets', 'countries.csv'): {"replacement": "<COUNTRIES>", "punctuation": None},
            }

        for field in fields:
            if fields[field]["punctuation"] is not None:
                for name in self.file_to_list(field):
                    for c in self._punctuation:
                        self.keyword_processor.add_keyword(
                            "{n}{c}".format(n=name, c=c),
                            "{n}{c}".format(n=fields[field]["replacement"], c=c)
                        )
            else:
                for name in self.file_to_list(field):
                    self.keyword_processor.add_keyword(name, fields[field]["replacement"])

        for name in self.file_to_list(os.path.join('datasets', 'firstnames.csv')):
            self.keyword_processor_names.add_keyword(name, "<NAME>")

        for name in self.file_to_list(os.path.join('datasets', 'lastnames.csv')):
            self.keyword_processor_names.add_keyword(name, "<NAME>")

        ul = '\u00a1-\uffff'  # Unicode letters range (must not be a raw string).

        # IP patterns
        ipv4_re = r'(?:0|25[0-5]|2[0-4]\d|1\d?\d?|[1-9]\d?)(?:\.(?:0|25[0-5]|2[0-4]\d|1\d?\d?|[1-9]\d?)){3}'
        ipv6_re = r'\[?((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,'\
                  r'4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{'\
                  r'1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2['\
                  r'0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,'\
                  r'3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|['\
                  r'1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,'\
                  r'2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|((['\
                  r'0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2['\
                  r'0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:['\
                  r'0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2['\
                  r'0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,'\
                  r'5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\]?'

        # Host patterns
        hostname_re = r'[a-z' + ul + r'0-9](?:[a-z' + ul + r'0-9-]{0,61}[a-z' + ul + r'0-9])?'
        # Max length for domain name labels is 63 characters per RFC 1034 sec. 3.1
        domain_re = r'(?:\.(?!-)[a-z' + ul + r'0-9-]{1,63}(?<!-))*'
        tld_re = (
                r'\.'                                # dot
                r'(?!-)'                             # can't start with a dash
                r'(?:[a-z' + ul + '-]{2,63}'         # domain label
                r'|xn--[a-z0-9]{1,59})'              # or punycode label
                r'(?<!-)'                            # can't end with a dash
                r'\.?'                               # may have a trailing dot
        )
        host_re = '(' + hostname_re + domain_re + tld_re + '|localhost)'

        self.url_re = re.compile(
            r'([a-z0-9.+-]*:?//)?'                                       # scheme is validated separately
            r'(?:[^\s:@/]+(?::[^\s:@/]*)?@)?'                           # user:pass authentication
            r'(?:' + ipv4_re + '|' + ipv6_re + '|' + host_re + ')'
            r'(?::\d{2,5})?'                                            # port
            r'(?:[/?#][^\s]*)?',                                        # resource path
            re.IGNORECASE
        )
        self.use_wordlist = wordlist_filter
        self.use_re = regular_expressions

        self.initialised = True

    @staticmethod
    def remove_numbers(text, set_zero=True):
        if set_zero:
            return re.sub('\d', '0', text).strip()
        else:
            return re.sub(r'\w*\d\w*', '<NUMBER>', text).strip()

    @staticmethod
    def remove_times(text):
        return re.sub('(\d{1,2})[.:](\d{1,2})?([ ]?(am|pm|AM|PM))?', '<TIME>', text)

    @staticmethod
    def remove_dates(text):
        text = re.sub("\d{2}[- /.]\d{2}[- /.]\d{,4}", "<DATE>", text)

        text = re.sub(
            "(\d{1,2}[^\w]{,2}(january|febuary|march|arpil|may|june|july|august|september|october|november|december)"
            "([- /.]{,2}(\d{4}|\d{2}))?)",
            "<DATE>", text)

        text = re.sub(
            "(\d{1,2}[^\w]{,2}(jan|feb|mrt|apr|mei|jun|jul|aug|sep|okt|nov|dec))[- /.](\d{4}|\d{2})?",
            "<DATE>", text)
        return text

    @staticmethod
    def remove_email(text):
        text = re.sub("(([a-zA-Z0-9_+]+(?:\.[\w-]+)*)@((?:[\w-]+\.)*\w[\w-]{0,66})\.([a-z]{2,6}(?:\.[a-z]{2})?))"
                      "(?![^<]*>)",
                      "<EMAIL>",
                      text)
        return text
        
    @staticmethod
    def remove_cc(text):
        text = re.sub("(?:4[0-9]{12}(?:[0-9]{3})?|[25][1-7][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})",
                      "<CREDITCARD>",
                      text)
        return text

    def remove_url(self, text):
        text = re.sub(self.url_re, "<URL>", text)
        return text
    
    @staticmethod
    def remove_postal_codes(text):
        text = re.sub(r"\d{6}", "<POSTCODE>", text)
        return text

    def filter_keyword_processors(self, text):
        text = self.keyword_processor.replace_keywords(text)
        text = self.keyword_processor_names.replace_keywords(text)
        return text

    def filter_regular_expressions(self, text, set_numbers_zero=True):
        text = self.remove_url(text)
        text = self.remove_cc(text)
        text = self.remove_dates(text)
        text = self.remove_times(text)
        text = self.remove_email(text)
        text = self.remove_postal_codes(text)
        text = self.remove_numbers(text, set_numbers_zero)
        return text

    @staticmethod
    def cleanup_text(result):
        result = re.sub("<[A-Z _]+>", "<FILTERED>", result)
        result = re.sub(" ([ ,.:;?!])", "\\1", result)
        result = re.sub(" +", " ", result)                          # remove multiple spaces
        result = re.sub("\n +", "\n", result)                       # remove space after newline
        result = re.sub("( <FILTERED>)+", " <FILTERED>", result)    # remove multiple consecutive <FILTERED> tags
        return result.strip()

    def filter(self, text, set_numbers_zero=False):
        if not self.initialised:
            self.initialize()

        text = self.filter_regular_expressions(text, set_numbers_zero)
        text = self.filter_keyword_processors(text)

        return self.cleanup_text(text)


def check_pii(sentence):
    print(sentence)
    
    pfilter = PrivacyFilter()
    pfilter.initialize()
    sentence = pfilter.filter(sentence, set_numbers_zero=False)
    
    print(sentence)
    if "FILTERED" in sentence:
        return True
        
if __name__ == "__main__":
    sentence = '''
5105105105105100
Tommy Chan is born in Singapore.
He lives at Ang Mo Kio Avenue 1 569830
He is a Singaporean.
You can learn more at ( https://tommychan.com )
You can contact tommy at tommylow@hotmail.com
This is an IPv4 address: 182.252.56.168
This is an IPv6 address: 8f20:bfe4:eda6:9026:ce64:b5a3:92c7:b4fb
The time now is 3:05pm
Tommy wants to visit China for the Winter Olympics    
'''
    check_pii(sentence)
# js-finder-burp-extentions
BurpJSLinkFinder-Enhanced is a Burp Suite extension (Jython 2.7) that extracts endpoints from JavaScript files, performs optional HEAD probing, and provides an interactive UI with live search, filtering and export to CSV/JSON. It includes heuristics for concatenated strings and base64/hex decoding and supports sending findings to Repeater or adding to scope.

# Key features

- Parse JS responses and extract endpoints via regex + simple patterns

- Live search across Endpoint, Source and Log

- Context-based priority tagging (HIGH when fetch/axios/XMLHttpRequest present)

- Decode embedded base64/hex strings and re-parse decoded content

- Optional background HEAD probing (concurrency control)

- Copy/open in browser/send to Repeater/add to scope UI actions

- Export results to CSV/JSON and clearable results

# Quick requirements & install

- Burp Suite (Extender tab)

- Jython standalone JAR configured in Burp

- Drop the .py file into Burp Extender and enable the extension

# pulse/parser.py
# ----------------
# This module handles reading Windows .evtx event log files.
#
# WHAT ARE .EVTX FILES?
# Windows records everything that happens on a computer in "event logs."
# These logs are stored as .evtx files (usually in C:\Windows\System32\winevt\Logs\).
# Each event has an ID number that tells you what happened:
#   - Event 4625 = Someone failed to log in
#   - Event 4720 = A new user account was created
#   - Event 4732 = Someone was added to a security group (possible privilege escalation)
#   - Event 1102 = The audit log was cleared (someone covering their tracks)
#
# This module reads those files and pulls out the events we care about.


import xml.etree.ElementTree as ET  # Built-in Python library for parsing XML data
from Evtx import Evtx              # Third-party library that knows how to read .evtx files


def parse_evtx(file_path):
    """
    Reads a .evtx file and returns a list of event dictionaries.

    Parameters:
        file_path (str): The path to the .evtx file to read.

    Returns:
        list: A list of dictionaries, where each dictionary represents
              one event from the log. Each dict has keys like:
              - "event_id": The Windows event ID number (e.g., 4625)
              - "timestamp": When the event happened
              - "data": The raw XML data from the event

    Example:
        events = parse_evtx("logs/Security.evtx")
        for event in events:
            print(event["event_id"], event["timestamp"])
    """

    # --- STEP 1: OPEN THE .EVTX FILE ---
    # PyEvtx gives us a class called "Evtx" that knows how to read these files.
    # We pass it the file path and it gives us an object we can loop through.
    # --- STEP 2: PREPARE AN EMPTY LIST TO COLLECT EVENTS ---
    # As we loop through the file, we'll build a dictionary for each event
    # and append it to this list. When we're done, we return the whole list.
    events = []

    # --- STEP 3: OPEN THE FILE AND LOOP THROUGH EVERY RECORD ---
    # The `with` statement ensures the file is properly closed when we're done,
    # even if an error occurs mid-way. This is required by the Evtx library.
    # evtx_file.records() is a generator — it gives us one record at a time
    # instead of loading the entire file into memory at once. This is important
    # because .evtx files can be HUGE (hundreds of MB for a busy server).
    with Evtx.Evtx(file_path) as evtx_file:
        for record in evtx_file.records():

            # --- STEP 3b: CAPTURE THE RECORD NUMBER ---
            # Windows assigns each event a sequential record number unique to that
            # log file. We use this in live-monitoring mode to know which events
            # we've already processed so we don't alert on them again.
            try:
                record_num = record.record_num()
            except Exception:
                record_num = None

            # --- STEP 4: GET THE RAW XML FOR THIS EVENT ---
            # Live log files can contain partially-written records (Windows was
            # mid-write when we read the file). We skip those rather than crash.
            try:
                xml_string = record.xml()
            except Exception:
                continue

            # --- STEP 5: PARSE THE XML TO EXTRACT FIELDS ---
            # xml.etree.ElementTree is Python's built-in XML parser.
            # ET.fromstring() takes an XML string and turns it into a tree
            # structure we can search through, kind of like a folder structure.
            try:
                xml_tree = ET.fromstring(xml_string)
            except ET.ParseError:
                continue

            # --- STEP 6: EXTRACT THE EVENT ID ---
            # Windows event XML uses "namespaces" — think of them as prefixes
            # that prevent name collisions (like how two people named "John"
            # might go by "John from Sales" and "John from Engineering").
            #
            # The namespace for Windows event logs is this long URL:
            ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
            #
            # The Event ID lives at: <System> -> <EventID>
            # .find() searches the XML tree for a specific tag.
            # .text gives us the actual text content inside that tag.
            event_id_element = xml_tree.find(f"{ns}System/{ns}EventID")

            # If we can't find an EventID (shouldn't happen, but let's be safe),
            # skip this record entirely rather than crashing.
            if event_id_element is None:
                continue

            # .text gives us a string like "4625", but we want an integer
            # so we can compare it to numbers later (e.g., if event_id == 4625).
            event_id = int(event_id_element.text)

            # --- STEP 7: EXTRACT THE TIMESTAMP ---
            # The timestamp is stored as an attribute on the <TimeCreated> tag.
            # An "attribute" is extra info attached to a tag, like:
            #   <TimeCreated SystemTime="2024-01-15T08:30:00.000Z" />
            # .get("SystemTime") pulls out the value of that attribute.
            time_created = xml_tree.find(f"{ns}System/{ns}TimeCreated")

            if time_created is not None:
                timestamp = time_created.get("SystemTime", "Unknown")
            else:
                timestamp = "Unknown"

            # --- STEP 8: BUILD THE DICTIONARY AND ADD IT TO OUR LIST ---
            # We package everything into a clean dictionary.
            # This is the format the rest of Pulse expects (detections.py, etc.).
            event_dict = {
                "event_id":   event_id,    # e.g., 4625
                "timestamp":  timestamp,   # e.g., "2024-01-15T08:30:00.000Z"
                "data":       xml_string,  # The full raw XML, in case we need it later
                "record_num": record_num,  # Sequential Windows record ID (used by monitor)
            }
            events.append(event_dict)

    # --- STEP 9: RETURN THE COMPLETE LIST ---
    # At this point we've looped through every record in the file.
    # The caller (main.py) gets back a list of dictionaries it can
    # pass to the detection engine.
    return events

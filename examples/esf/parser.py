import json
import argparse


def parse_jsonl_file(path):
    """
    Parses a JSONL file and returns a list of JSON objects.

    Args:
        path (str): The path to the JSONL file.

    Returns:
        list: A list of JSON objects parsed from the file.
    """
    with open(path, "r") as file:
        return [json.loads(line.strip()) for line in file if line.strip()]


def extract_unlink_details(unlink_event):
    """
    Extracts details from an unlink event.

    Args:
        unlink_event (dict): The unlink event JSON object.

    Returns:
        dict: A dictionary containing the extracted details.
    """
    process_event = unlink_event.get("process", {})
    unlink_event_details = unlink_event.get("event", {}).get("unlink", {})
    return {
        "time": unlink_event.get("time", "N/A"),
        "pid": process_event.get("audit_token", {}).get("pid", "N/A"),
        "ppid": process_event.get("ppid", "N/A"),
        "rpid": process_event.get("responsible_audit_token", {}).get("pid", "N/A"),
        "executable_path": process_event.get("executable", {}).get("path", "N/A"),
        "file_path": unlink_event_details.get("target", {}).get("path", "N/A"),
    }


def extract_create_details(create_event):
    """
    Extracts details from a create event.

    Args:
        create_event (dict): The create event JSON object.

    Returns:
        dict: A dictionary containing the extracted details.
    """
    process_event = create_event.get("process", {})
    create_event_details = create_event.get("event", {}).get("create", {})
    return {
        "time": create_event.get("time", "N/A"),
        "pid": process_event.get("audit_token", {}).get("pid", "N/A"),
        "ppid": process_event.get("ppid", "N/A"),
        "rpid": process_event.get("responsible_audit_token", {}).get("pid", "N/A"),
        "executable_path": process_event.get("executable", {}).get("path", "N/A"),
        "file_path": create_event_details.get("destination", {})
        .get("existing_file", {})
        .get("path", "N/A"),
    }


def extract_open_details(open_event):
    """
    Extracts details from an open event.

    Args:
        open_event (dict): The open event JSON object.

    Returns:
        dict: A dictionary containing the extracted details.
    """
    process_event = open_event.get("process", {})
    open_event_details = open_event.get("event", {}).get("open", {})
    return {
        "time": open_event.get("time", "N/A"),
        "pid": process_event.get("audit_token", {}).get("pid", "N/A"),
        "ppid": process_event.get("ppid", "N/A"),
        "rpid": process_event.get("responsible_audit_token", {}).get("pid", "N/A"),
        "executable_path": process_event.get("executable", {}).get("path", "N/A"),
        "file_path": open_event_details.get("file", {}).get("path", "N/A"),
    }


def extract_exec_details(exec_event):
    """
    Extracts details from an exec event.

    Args:
        exec_event (dict): The exec event JSON object.

    Returns:
        dict: A dictionary containing the extracted details.
    """
    exec_event_details = exec_event.get("event", {}).get("exec", {})
    return {
        "time": exec_event.get("time", "N/A"),
        "pid": exec_event_details.get("target", {})
        .get("audit_token", {})
        .get("pid", "N/A"),
        "ppid": exec_event_details.get("target", {}).get("ppid", "N/A"),
        "rpid": exec_event_details.get("target", {})
        .get("responsible_audit_token", {})
        .get("pid", "N/A"),
        "executable_path": exec_event_details.get("target", {})
        .get("executable", {})
        .get("path", "N/A"),
        "args": exec_event_details.get("args", "N/A"),
    }


def extract_tcc_details(event):
    """
    Extracts details from a TCC modify event.

    Args:
        tcc_event (dict): The TCC modify event JSON object.

    Returns:
        dict: A dictionary containing the extracted details.
    """
    process_event = event.get("process", {})
    tcc_event = event.get("event", {}).get("tcc_modify", {})
    right_details = {}
    if tcc_event.get("right"):
        right = tcc_event.get("right")
        if right in TCC_AUTHORIZATION_RIGHTS:
            right_details["authorization"] = TCC_AUTHORIZATION_RIGHTS[right]
            right_details["allowed_identity"] = tcc_event.get("identity", "N/A")
        else:
            print("Unknown authorization right:", right)

    return {
        "time": event.get("time", "N/A"),
        "instigator": tcc_event.get("instigator", "N/A")
        .get("executable", {})
        .get("path", "N/A"),
        "pid": process_event.get("audit_token", {}).get("pid", "N/A"),
        "ppid": process_event.get("ppid", "N/A"),
        "rpid": process_event.get("responsible_audit_token", {}).get("pid", "N/A"),
        "executable_path": process_event.get("executable", {}).get("path", "N/A"),
        "service": tcc_event.get("service", "N/A"),
        "right_details": right_details,
    }


ESF_EVENTS = {
    9: ("exec", extract_exec_details),
    10: ("open", extract_open_details),
    13: ("create", extract_create_details),
    32: ("unlink", extract_unlink_details),
    147: ("tcc_modify", extract_tcc_details),
}

"""
https://github.com/alexey-lysiuk/macos-sdk/blob/e96f557d53a0282abc7c93a76a802605b20e4282/MacOSX15.5.sdk/usr/include/EndpointSecurity/ESTypes.h
"""
TCC_AUTHORIZATION_RIGHTS = {
    0: "DENIED",
    1: "UNKNOWN",
    2: "ALLOWED",
    3: "LIMITED",
    4: "ADD_MODIFY_ADDED",
    5: "SESSION_PID",
    6: "LEARN_MORE",
}


def process_events(events):
    for json_blob in events:
        if event_type := json_blob.get("event_type"):
            if event_type in ESF_EVENTS:
                event_name, extractor = ESF_EVENTS[event_type]
                print(f"Processing event: {event_name}")
                extracted_details = extractor(json_blob)
                print(
                    f"{event_name.capitalize()} Details: {json.dumps(extracted_details, indent=2)}"
                )
                print("-" * 40)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse macOS Endpoint Security logs.")
    parser.add_argument(
        "path", type=str, help="Path to the JSONL file containing the logs."
    )

    args = parser.parse_args()
    path = args.path
    print(f"Parsing logs from: {path}")

    events = parse_jsonl_file(path)
    process_events(events)

    print("Processing completed.")
    print("Total events processed:", len(events))

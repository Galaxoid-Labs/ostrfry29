package main

import "core:bufio"
import "core:encoding/ini"
import "core:encoding/json"
import "core:fmt"
import "core:os"
import "core:os/os2"
import "core:strings"
import "onostr"

InputMessage :: struct {
	type:        string `json:"type"`,
	event:       onostr.Event `json:"event"`,
	received_at: i64 `json:"receivedAt"`,
	source_type: string `json:"sourceType"`,
	source_info: string `json:"sourceType"`,
}

OutputMessage :: struct {
	id:     string `json:"id"`,
	action: string `json:"action"`,
	msg:    string `json:"msg"`,
}

NIP29_KINDS :: [?]int {
	9,
	10,
	11,
	12,
	9000,
	9001,
	9002,
	9003,
	9004,
	9005,
	9007,
	9008,
	9021,
	9022,
	39000,
	39001,
	39002,
	39003,
}

main :: proc() {

	// Read ini file for configuration
	config, err, ok := ini.load_map_from_path("config.ini", context.allocator)
	defer delete(config)
	if !ok {
		panic("Failed to load config.ini")
	}

	pk_hex := config["config"]["pk_hex"]

	// Create KeyPair for signing
	kp, kpok := onostr.make_keypair_from_hex(pk_hex).?
	defer if kpok {
		onostr.destroy_keypair(&kp)
	}
	if !kpok {
		panic("Failed to create keypair")
	}

	strfry_cmd_path := config["config"]["strfry_cmd_path"]
	if strfry_cmd_path == "" {
		strfry_cmd_path = "strfry"
	}

	reader: bufio.Reader
	bufio.reader_init(&reader, os.stream_from_handle(os.stdin))
	defer bufio.reader_destroy(&reader)

	for {

		// Set allocator to temp_allocator for the current context
		context.allocator = context.temp_allocator

		// Clear all allocations in temp_allocator at the end of the loop iteration
		defer free_all(context.temp_allocator)

		line, err := bufio.reader_read_string(&reader, '\n')
		if err != nil {
			break
		}
		line = strings.trim_right_space(line)

		accept(line)

	}
}

accept :: proc(id: string) {

	msg := OutputMessage {
		id     = id,
		action = "accept",
		msg    = "",
	}

	json_bytes, err := json.marshal(msg)
	if err != nil {
		panic("Failed to marshal JSON")
	}

	fmt.println(string(json_bytes))
	os.flush(os.stdout)
}

reject :: proc(id: string, msg: string) {

	msg := OutputMessage {
		id     = id,
		action = "reject",
		msg    = msg,
	}

	json_bytes, err := json.marshal(msg)
	if err != nil {
		panic("Failed to marshal JSON")
	}

	fmt.println(string(json_bytes))
	os.flush(os.stdout)
}

query_with_command :: proc(cmd: []string) -> [dynamic]onostr.Event {

	process_desc := os2.Process_Desc {
		command = cmd,
		stdin   = os2.stdin,
	}

	_, so, _, _ := os2.process_exec(process_desc, context.allocator)
	lines := strings.split_lines(string(so))

	events := make([dynamic]onostr.Event, context.allocator)

	for line in lines {

		if len(line) == 0 {
			continue
		}

		event: onostr.Event
		err := json.unmarshal_string(line, &event)
		if err != nil {
			continue
		}

		append(&events, event)
	}

	return events
}

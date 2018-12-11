import frida
import sys

def on_message(message, data):
    print("[*]message:", message, "data:", data)

def on_detached():
    print("[*]detached!")


def main():
    if len(sys.argv) < 2:
        print('Usage: %s <process name or PID>' % sys.argv[0])
        sys.exit(1)
    try:
        target_process = int(sys.argv[1])
    except ValueError:
        target_process = sys.argv[1]

    # First, let's attach to the process
    session = frida.attach(target_process)

    #send message to Python process
    script = session.create_script("""
        send('test msg from js');

        Interceptor.attach(Module.findExportByName("IOKit", "IOConnectCallMethod"), {
            onEnter: function (args) {
                console.log("[*]IOConnectCallMethod called");
                var connection = args[0].toInt32();
                var selector = args[1].toInt32();

                // Scalar input arguments
                var input_scalar = args[2]; // const uint64_t *input
                var input_scalar_count = args[3].toInt32(); // uint32_t inputCnt

                // Struct input arguments
                var input_struct = args[4]; // const void *inputStruct
                var input_struct_count = args[5].toInt32(); // size_t inputStructCnt

                // Scalar output arguments
                var output_scalar = args[6]; // uint64_t *output
                var output_scalar_count = 0; // uint32_t outputCnt

                payload = {
                //"service_name" : user_client,
                //"service_type" : user_client_type,
                //"selector" : selector,
                //"input_scalar" : input_scalar_arr,
                //"input_scalar_count" : input_scalar_count,
                //"input_struct_count" : input_struct_count,
                //"output_scalar_count" : output_scalar_count,
                //"output_scalar" : output_scalar_arr,
                //"output_struct_count" : output_struct_count,
                };
                send(payload);
                }
        });
""")

    script.on("message", on_message)
    session.on('detached',on_detached)
    script.load()
    sys.stdin.read()

if __name__ == '__main__':
    main()

import frida
import sys
import time

def on_message(message, data):
    print("[*]message:", message, "data:", data)

def on_detached():
    print("[*]detached!")
    sys.exit(1)


def main():
    if len(sys.argv) < 2:
        print('Usage: %s <process name or PID>' % sys.argv[0])
        sys.exit(1)
    try:
        target_process = int(sys.argv[1])
    except ValueError:
        target_process = sys.argv[1]

    # First, let's attach to the process
    while True:
        try:
            session = frida.attach(target_process)
            break
        except frida.ProcessNotFoundError:
            time.sleep(0)

    #can't work on safari
    #pid = frida.spawn(target_process)
    #session = frida.attach(pid)

    # send message to Python process
    script = session.create_script("""
        send('test msg from js');

        var service_ids=new Array();

        //kern_return_t IOConnectCallMethod(mach_port_t connection, uint32_t selector, const uint64_t *input, uint32_t inputCnt, const void *inputStruct,
        //                                        size_t inputStructCnt, uint64_t *output, uint32_t *outputCnt, void *outputStruct, size_t *outputStructCnt);

        Interceptor.attach(Module.findExportByName("IOKit", "IOConnectCallMethod"), {
            onEnter: function (args) {
                console.log("[*]IOConnectCallMethod called");
                var connection = args[0].toInt32();
                var selector = args[1].toInt32();
                console.log("IOConnectCallMethod connection = " + connection);


                // Scalar input arguments
                var input_scalar = args[2]; // const uint64_t *input
                var input_scalar_count = args[3].toInt32(); // uint32_t inputCnt

                // Struct input arguments
                var input_struct = args[4]; // const void *inputStruct
                var input_struct_count = args[5].toInt32(); // size_t inputStructCnt

                // Scalar output arguments
                var output_scalar = args[6]; // uint64_t *output
                var output_scalar_count = 0; // uint32_t outputCnt

                var user_client = service_ids[connection][0];
                var user_client_type = service_ids[connection][1];

                payload = {
                "service_name" : user_client,
                "service_type" : user_client_type,
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

//        Interceptor.attach(Module.findExportByName("IOKit", "IOServiceMatching"), {
//            onEnter: function (args) {
//                console.log("[*]IOServiceMatching called");
//                //var user_client = args[0].toString();
//                var user_client = Memory.readUtf8String(args[0]);
//
//                payload = {
//                "service_name" : user_client,
//                };
//                send(payload);
//                }
//        });
//
//        Interceptor.attach(Module.findExportByName("IOKit", "IOServiceGetMatchingServices"), {
//            onEnter: function (args) {
//                console.log("[*]IOServiceGetMatchingServices called");
//                }
//         });
//
//        Interceptor.attach(Module.findExportByName("IOKit", "IOServiceGetMatchingService"), {
//            onEnter: function (args) {
//                console.log("[*]IOServiceGetMatchingService called");
//                }
//        });

        //kern_return_t IOServiceOpen(io_service_t service, task_port_t owningTask, uint32_t type, io_connect_t *connect);

        Interceptor.attach(Module.findExportByName("IOKit", "IOServiceOpen"), {
            onEnter: function (args) {
                console.log("[*]IOServiceOpen called");
                connect_ptr = args[3]; // io_connect_t *connect
                classname = Memory.alloc(256); // Temp buffer to hold class name on the heap.
                // Determine the class name of the IOKit object
                var IOObjectGetClass = Module.findExportByName(null, "IOObjectGetClass");
                //var IOObjectGetClassFunc = new NativeFunction(ptr(IOObjectGetClass), 'int', ['pointer','pointer']);//???why use prt() by v9.
		var IOObjectGetClassFunc = new NativeFunction(IOObjectGetClass, 'int', ['pointer','pointer']); //working OK.
                IOObjectGetClassFunc(args[0],classname);
                console.log("IOObjectGetClass = " + Memory.readUtf8String(classname));
                type = args[2];
                console.log("IOServiceOpen(" + args[0] + "," + args[1] + "," + args[2] + "," + args[3] + ");");
        },
            onLeave: function (retval) {
                // If we have a valid connection
                if (retval == 0) {
                var handle = Memory.readU32(connect_ptr);
                var userclient = Memory.readUtf8String(classname);
                console.log("IOServiceOpen ret = " + handle);
                console.log("IOServiceOpen userclient = " + userclient);
                console.log("IOServiceOpen type = " + type);
                // Store the details in the map
                service_ids[handle] = [userclient,type];
                }
            }
        });


""")

    script.on("message", on_message)
    session.on('detached',on_detached)
    script.load()
    #frida.resume(pid)
    sys.stdin.read()

if __name__ == '__main__':
    main()


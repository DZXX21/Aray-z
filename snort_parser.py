import re

key_list = []
value_list = []


def read_file(file_name):

    f = open(file_name, 'r')
    start_line = f.readlines()

    for i in start_line[0:]:

        print("************ALERT START************")

        x = re.search(r'^((?:[0-9]{2}[-\/:.]){5}[0-9]{6})(.*[{]TCP[}]\s*|.*[{]UDP[}]\s*|.*[{]ICMP[}]\s*).(.*)', i)

        if x is not None:
            date_time = x.group(1)
            event = x.group(2).lstrip()
            ip_info = x.group(3)
        else:
            print("Eşleşme bulunamadı:", i)
            continue

        value_list.append(date_time)
        key_list.append("time")
        print(date_time)
        print(event)

        if "{ICMP}" in event:

            icmp_formatted = re.search(r'((?:[0-9]{1,3}[.]){1,3}[0-9]{1,3})\s*->\s*((?:[0-9]{1,3}[.]){1,3}[0-9]{1,3})', ip_info)

            if icmp_formatted is not None:
                icmp_src_ip = icmp_formatted.group(1)
                key_list.append("srcip")
                icmp_src_port = "none"
                key_list.append("srcport")
                icmp_dest_ip = icmp_formatted.group(2)
                key_list.append("destip")
                icmp_dest_port = "none"
                key_list.append("destport")
                print(icmp_src_ip)
                print(icmp_dest_ip)

                value_list.append(icmp_src_ip)
                value_list.append(icmp_src_port)
                value_list.append(icmp_dest_ip)
                value_list.append(icmp_dest_port)

                get_event_desc = re.search(r'(.*\s[[][*][*][]])(.*\s[[]Classification:.*[[])', event)

                if get_event_desc is not None:
                    event_desc = get_event_desc.group(1)
                    classification = get_event_desc.group(2)[:-3].lstrip()[17:]

                    value_list.append(event_desc)
                    value_list.append(classification)
                    key_list.append("event")
                    key_list.append("classification")

                    print(event_desc)
                    print(classification)
                else:
                    print("Etkinlik açıklaması bulunamadı.")
            else:
                print("ICMP formatı bulunamadı.")

        elif "{TCP}" or "{UDP}" in event:

            ip_formatted = re.search(r'\s*(((?:[0-9]{1,3}[.]){1,3}[0-9]{1,3}):([0-9]{1,6}))\s*->\s*(((?:[0-9]{1,3}[.]){1,3}[0-9]{1,3}):([0-9]{1,6}))', ip_info)

            if ip_formatted is not None:
                src_ip = ip_formatted.group(2)
                key_list.append("srcip")
                src_port = ip_formatted.group(3)
                key_list.append("srcport")
                dest_ip = ip_formatted.group(5)
                key_list.append("destip")
                dest_port = ip_formatted.group(6)
                key_list.append("destport")

                value_list.append(src_ip)
                value_list.append(src_port)
                value_list.append(dest_ip)
                value_list.append(dest_port)

                print(src_ip)
                print(src_port)
                print(dest_ip)
                print(dest_port)

                get_event_desc = re.search(r'(.*\s[[][*][*][]])(.*\s[[]Classification:.*[[])', event)

                if get_event_desc is not None:
                    event_desc = get_event_desc.group(1)
                    classification = get_event_desc.group(2)[:-3].lstrip()[17:]

                    value_list.append(event_desc)
                    value_list.append(classification)
                    key_list.append("event")
                    key_list.append("classification")

                    print(event_desc)
                    print(classification)
                else:
                    print("Etkinlik açıklaması bulunamadı.")
            else:
                print("IP formatı bulunamadı.")

        print("************ALERT END************")

    f.close()

    n = 7
    snort_list = [value_list[i * n:(i + 1) * n] for i in range((len(value_list) + n - 1) // n)]
    return snort_list

# Örnek kullanım:
# snort_output_list = read_file('dosya_adı.log')
# print(snort_output_list)

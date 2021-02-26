import dpkt
import geoip2.database
import socket
import pandas as pd


def ip_geo_info_(target):
    with geoip2.database.Reader('GeoLite2/GeoLite2-City.mmdb') as reader:
        try:
            resp = reader.city(target)
        except:
            return ["Unknown", "Unknown", "Unknown", "Unknown", "Unknown"]
        city = resp.city.name
        region = resp.subdivisions.most_specific.name
        iso = resp.country.iso_code
        lat = resp.location.latitude
        long = resp.location.longitude
        data = [city, region, iso, lat, long]
        for i in range(len(data)):
            if data[i] is None:
                data[i] = "Unknown"
        return data


def loc_array_pcap(pcap):
    result = []
    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            src_info = ip_geo_info_(src)
            dst_info = ip_geo_info_(dst)
            full_info = [src]
            full_info.extend(src_info)
            full_info.append(dst)
            full_info.extend(dst_info)
            result.append(full_info)
        except:
            pass
    return result


f = open('pcaps/2020-08-21-traffic-analysis-exercise.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)
loc_data = loc_array_pcap(pcap)
df = pd.DataFrame(loc_data, columns=['Source IP', 'S City', 'S Region', 'S Country', 'S Lat', 'S Long',
                                     'Destination IP', 'D City', 'D Region', 'D Country', 'D Lat', 'D Long'])
df.to_csv('out/finished.csv')
print(ip_geo_info_('122.124.6.1'))
print(ip_geo_info_('192.168.0.0'))

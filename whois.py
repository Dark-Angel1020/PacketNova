import requests
import sys

def print_rdap_info(ip):
    """Fetch and display basic RDAP information for an IP address"""
    rdap_url = f"https://rdap.apnic.net/ip/{ip}"
    
    try:
        response = requests.get(rdap_url)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching RDAP data: {e}")
        sys.exit(1)
    print(f"Information for: {ip}")
    print(f"Network Name:    {data.get('name', 'N/A')}")
    print(f"Network Handle:  {data.get('handle', 'N/A')}")
    print(f"Country:         {data.get('country', 'N/A')}")
    print(f"IP Range:        {data.get('startAddress', 'N/A')} - {data.get('endAddress', 'N/A')}")
    if 'status' in data:
        print(f"Status:          {', '.join(data['status'])}")
        print("----------------------------------")
    if 'entities' in data:
        abuse = next((entity for entity in data['entities'] if 'roles' in entity and 'abuse' in entity['roles']), None)
        if abuse and 'vcardArray' in abuse and len(abuse['vcardArray']) > 1:
            vcard = abuse['vcardArray'][1]
            email = next((item for item in vcard if item[0] == 'email'), None)
            
            if email:
                print("Abuse Contact Info")
                print(f"Email:           {email[3]}")
            print("----------------------------------")
    if 'entities' in data:
        print("Other Contacts")
        
        for entity in data['entities']:
            if 'roles' not in entity or 'abuse' in entity.get('roles', []):
                continue
                
            if 'vcardArray' in entity and len(entity['vcardArray']) > 1:
                vcard = entity['vcardArray'][1]
                
                print(f"Entity Handle:   {entity.get('handle', 'N/A')}")
                print(f"Roles:           {', '.join(entity.get('roles', ['Unknown']))}")
                
                name = next((item for item in vcard if item[0] == 'fn'), None)
                if name:
                    print(f"Name:            {name[3]}")
                
                email = next((item for item in vcard if item[0] == 'email'), None)
                if email:
                    print(f"Email:           {email[3]}")
                
                tel = next((item for item in vcard if item[0] == 'tel'), None)
                if tel:
                    print(f"Phone:           {tel[3]}")
                
                print("----------------------------------")
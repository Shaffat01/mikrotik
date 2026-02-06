from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from librouteros import connect
import sqlite3
import logging

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# --- ডাটাবেস সেটআপ ---
def init_db():
    conn = sqlite3.connect('network.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS routers 
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, ip TEXT)''')
    conn.commit()
    conn.close()

init_db()

def connect_to_mikrotik():
    if 'target_ip' not in session:
        return None
    return connect(
        host=session['target_ip'], 
        username=session['target_user'], 
        password=session['target_pass'],
        timeout=10
    )

# --- মেইন রাউটার লিস্ট (Home Page) ---
@app.route('/')
def home():
    conn = sqlite3.connect('network.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM routers")
    routers = cursor.fetchall()
    conn.close()
    return render_template('home.html', routers=routers)

# নতুন রাউটার অ্যাড করা
@app.route('/add-router', methods=['POST'])
def add_router():
    name = request.form.get('name')
    ip = request.form.get('ip')
    if name and ip:
        conn = sqlite3.connect('network.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO routers (name, ip) VALUES (?, ?)", (name, ip))
        conn.commit()
        conn.close()
    return redirect(url_for('home'))

# রাউটার ডিলিট করা
@app.route('/delete-router/<int:id>')
def delete_router(id):
    conn = sqlite3.connect('network.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM routers WHERE id=?", (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('home'))

# --- মাইক্রোটিক লগইন পেজ ---
@app.route('/configure/mikrotik')
def mikrotik_auth_page():
    target_ip = request.args.get('ip', '') 
    return render_template('router_auth.html', target_ip=target_ip)

@app.route('/mikrotik/authenticate', methods=['POST'])
def mikrotik_authenticate():
    session['target_ip'] = request.form['router_ip']
    session['target_user'] = request.form['router_user']
    session['target_pass'] = request.form['router_pass']
    
    try:
        # কানেকশন টেস্ট
        api = connect(host=session['target_ip'], username=session['target_user'], 
                password=session['target_pass'], timeout=5)
        return redirect(url_for('mikrotik_gui_main'))
    except Exception as e:
        flash(f"Authentication Failed: {str(e)}", "danger")
        return redirect(url_for('mikrotik_auth_page', ip=session['target_ip']))

# --- ড্যাশবোর্ড ---
@app.route('/mikrotik/gui-main')
def mikrotik_gui_main():
    if 'target_ip' not in session: return redirect('/')
    try:
        api = connect(host=session['target_ip'], username=session['target_user'], password=session['target_pass'])
        resource = list(api.path('/system/resource').select())[0]
        interfaces = list(api.path('/interface').select())
        addresses = list(api.path('/ip/address').select())
        return render_template('mikrotik_dashboard.html', res=resource, interfaces=interfaces, ip_addresses=addresses)
    except:
        return redirect(url_for('logout'))

@app.route('/mikrotik/ip-list')
def ip_list_page():
    if 'target_ip' not in session: return redirect('/')
    api = connect(host=session['target_ip'], username=session['target_user'], password=session['target_pass'])
    addresses = list(api.path('ip', 'address').select())
    interfaces = list(api.path('interface').select())
    return render_template('mikrotik_ip_addresses.html', ip_addresses=addresses, interfaces=interfaces)

################# ip add #################
@app.route('/mikrotik/add-ip', methods=['POST'])
def add_ip_logic():
    if 'target_ip' not in session: return redirect('/')
    
    new_ip = request.form.get('address')
    target_interface = request.form.get('interface')

    try:
        api = connect(host=session['target_ip'], username=session['target_user'], password=session['target_pass'])
        api.path('ip', 'address').add(address=new_ip, interface=target_interface)
        return redirect(url_for('ip_list_page'))
    except Exception as e:
        return f"Error adding IP: {str(e)}"

################### ip enable/disable#####################

@app.route('/mikrotik/toggle-ip', methods=['POST'])
def toggle_ip():
    if 'target_ip' not in session: return redirect('/')
    
    ip_id = request.form.get('ip_id')
    current_status = request.form.get('current_status')
    new_disabled_state = False if (current_status.lower() == 'true' or current_status == 'yes') else True
    
    try:
        api = connect(host=session['target_ip'], username=session['target_user'], password=session['target_pass'])
        
        api.path('ip', 'address').update(**{
            '.id': ip_id, 
            'disabled': new_disabled_state
        })
        
        return redirect(url_for('ip_list_page'))
    except Exception as e:
        return f"Error updating IP: {str(e)} <br><a href='/mikrotik/ip-list'>Go Back</a>"

################ mikrotik ip delete###########################
@app.route('/mikrotik/delete-ip', methods=['POST'])
def delete_ip():
    if 'target_ip' not in session: return redirect('/')
    ip_id = request.form.get('ip_id')
    try:
        api = connect(host=session['target_ip'], username=session['target_user'], password=session['target_pass'])
        api.path('ip', 'address').remove(ip_id)
        return redirect(url_for('ip_list_page'))
    except Exception as e:
        return f"Error: {str(e)}"

########################ip adress Edit#########################
@app.route('/mikrotik/edit-ip', methods=['POST'])
def edit_ip():
    if 'target_ip' not in session: return redirect('/')
    try:
        api = connect_to_mikrotik()
        ip_id = request.form['ip_id']
        new_address = request.form['address']
        new_interface = request.form['interface']
        api.path('/ip/address').update(**{
            '.id': ip_id,
            'address': new_address,
            'interface': new_interface
        })

        return redirect(url_for('ip_list_page')) 
    except Exception as e:
        return f"Update Error: {str(e)}"


################ mikrotik interface ###########################

@app.route('/mikrotik/interfaces')
def list_interfaces():
    if 'target_ip' not in session: return redirect(url_for('mikrotik_auth_page'))
    try:
        api = connect(host=session['target_ip'], username=session['target_user'], password=session['target_pass'])
        interface_list = list(api.path('/interface').select())

        def convert_to_human(bytes_val):
            try:
                bytes_val = int(bytes_val)
                if bytes_val < 1024 * 1024: return f"{round(bytes_val/1024, 2)} KB"
                elif bytes_val < 1024 * 1024 * 1024: return f"{round(bytes_val/(1024*1024), 2)} MB"
                else: return f"{round(bytes_val/(1024*1024*1024), 2)} GB"
            except: return "0 B"

        for iface in interface_list:
            rx = iface.get('rx-byte') or iface.get('rx-bytes') or 0
            tx = iface.get('tx-byte') or iface.get('tx-bytes') or 0
            iface['mac_address'] = iface.get('mac-address', 'N/A')
            iface['rx_total'] = convert_to_human(rx)
            iface['tx_total'] = convert_to_human(tx)
            iface['is_disabled'] = str(iface.get('disabled', 'false')).lower()

        return render_template('mikrotik_interfaces.html', interfaces=interface_list)
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/mikrotik/interface-traffic/<name>')
def get_traffic_data(name):
    if 'target_ip' not in session: return jsonify({"tx": "0 bps", "rx": "0 bps"}), 401
    try:
        api = connect(host=session['target_ip'], username=session['target_user'], password=session['target_pass'])
        traffic = api.path('/interface/monitor-interface')(interface=name, once=True)
        
        if traffic:
            tx_bps = traffic[0].get('tx-bits-per-second') or traffic[0].get('tx_bits_per_second') or 0
            rx_bps = traffic[0].get('rx-bits-per-second') or traffic[0].get('rx_bits_per_second') or 0
        else: tx_bps, rx_bps = 0, 0

        def format_speed(bps):
            bps = int(bps)
            if bps < 1000: return f"{bps} bps"
            elif bps < 1000000: return f"{round(bps/1000, 1)} Kbps"
            else: return f"{round(bps/1000000, 2)} Mbps"

        return jsonify({"tx": format_speed(tx_bps), "rx": format_speed(rx_bps)})
    except:
        return jsonify({"tx": "0 bps", "rx": "0 bps"})

@app.route('/mikrotik/interface/disable/<name>')
def disable_interface(name):
    try:
        api = connect(host=session['target_ip'], username=session['target_user'], password=session['target_pass'])
        api.path('/interface').update(**{'.id': name, 'disabled': 'yes'})
        return redirect(url_for('list_interfaces'))
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/mikrotik/interface/enable/<name>')
def enable_interface(name):
    try:
        api = connect(host=session['target_ip'], username=session['target_user'], password=session['target_pass'])
        api.path('/interface').update(**{'.id': name, 'disabled': 'no'})
        return redirect(url_for('list_interfaces'))
    except Exception as e:
        return f"Error: {str(e)}"


#######################VLAN##########################################

@app.route('/mikrotik/networks/vlan')
def list_vlan():
    if 'target_ip' not in session: return redirect('/')
    try:
        api = connect_to_mikrotik()
        vlans = list(api.path('/interface/vlan').select())
        interfaces = list(api.path('/interface').select())
        return render_template('mikrotik_vlan.html', vlans=vlans, interfaces=interfaces)
    except Exception as e:
        return f"VLAN Load Error: {str(e)}"

######################ADD VLAN###############################
@app.route('/mikrotik/networks/vlan/add', methods=['POST'])
def add_vlan():
    if 'target_ip' not in session: return redirect('/')
    
    try:
        v_name = request.form['name']
        v_id = request.form['vlan_id']
        v_interface = request.form['interface']
        api = connect_to_mikrotik()
        api.path('/interface/vlan').add(**{
            'name': v_name,
            'vlan-id': v_id,
            'interface': v_interface
        })
        
        return redirect(url_for('list_vlan'))
    except Exception as e:
        return f"VLAN Add Error: {str(e)} <br><a href='/mikrotik/networks/vlan'>Go Back</a>"

###################### DELETE VLAN #############################

@app.route('/mikrotik/networks/vlan/delete/<id>')
def delete_vlan(id):
    if 'target_ip' not in session: return redirect('/')
    try:
        api = connect_to_mikrotik()
        api.path('/interface/vlan').remove(id)
        return redirect(url_for('list_vlan'))
    except Exception as e:
        return f"Delete Error: {str(e)}"

########################## EDIT VLAN ###########################

@app.route('/mikrotik/networks/vlan/edit', methods=['POST'])
def edit_vlan():
    if 'target_ip' not in session: return redirect('/')
    try:
        api = connect_to_mikrotik()
        vlan_internal_id = request.form['vlan_id_internal']
        api.path('/interface/vlan').update(**{
            '.id': vlan_internal_id,
            'name': request.form['name'],
            'vlan-id': request.form['vlan_id'],
            'interface': request.form['interface'],
            'mtu': request.form['mtu']
        })
        
        return redirect(url_for('list_vlans')) 
    except Exception as e:
        return f"VLAN Update Error: {str(e)}"

######################DHCP SERVER###########################
# DHCP Server List
@app.route('/mikrotik/networks/dhcp-server')
def list_dhcp_server():
    if 'target_ip' not in session: return redirect('/')
    try:
        api = connect_to_mikrotik()
        dhcp_servers = list(api.path('/ip/dhcp-server').select())
        networks = list(api.path('/ip/dhcp-server/network').select())
        pools = list(api.path('/ip/pool').select())
        interfaces = list(api.path('/interface').select())

        full_dhcp_data = []
        for srv in dhcp_servers:
            p_name = srv.get('address-pool')
            pool_info = next((p for p in pools if p['name'] == p_name), None)
            ip_range = pool_info.get('ranges', '') if pool_info else ''
            target_net = {}
            if ip_range:
                first_ip = ip_range.split('-')[0].strip()
                ip_prefix = ".".join(first_ip.split('.')[:3]) + "." 
                
                target_net = next((n for n in networks if n.get('address', '').startswith(ip_prefix)), {})

            full_dhcp_data.append({
                '.id': srv.get('.id'),
                'name': srv.get('name'),
                'interface': srv.get('interface'),
                'pool_name': p_name,
                'ip_range': ip_range if ip_range else 'Static Only',
                'network': target_net.get('address', 'Not Defined'),
                'dns': target_net.get('dns-server', ''),
                'disabled': srv.get('disabled')
            })

        return render_template('mikrotik_dhcp_server.html', 
                               servers=full_dhcp_data, 
                               interfaces=interfaces, 
                               pools=pools)
    except Exception as e:
        return f"Error: {str(e)}"

########################### Add DHCP Server ##################################
@app.route('/mikrotik/networks/dhcp-server/add', methods=['POST'])
def add_dhcp_server():
    if 'target_ip' not in session: return redirect('/')
    try:
        api = connect_to_mikrotik()
        api.path('/ip/dhcp-server').add(**{
            'name': request.form['name'],
            'interface': request.form['interface'],
            'address-pool': request.form['pool'],
            'disabled': 'no'
        })
        return redirect(url_for('list_dhcp_server'))
    except Exception as e:
        return f"Add Error: {str(e)}"

########################### Delete DHCP Server ##############################
@app.route('/mikrotik/networks/dhcp-server/delete/<id>')
def delete_dhcp_server(id):
    if 'target_ip' not in session: return redirect('/')
    try:
        api = connect_to_mikrotik()
        api.path('/ip/dhcp-server').remove(id)
        return redirect(url_for('list_dhcp_server'))
    except Exception as e:
        return f"Delete Error: {str(e)}"

########################### EDIT DHCP Server ##############################

@app.route('/mikrotik/networks/dhcp-server/edit', methods=['POST'])
def edit_dhcp_server():
    if 'target_ip' not in session: return redirect('/')
    try:
        api = connect_to_mikrotik()
        server_id = request.form['server_id']
        api.path('/ip/dhcp-server').update(**{
            '.id': server_id,
            'name': request.form['name'],
            'interface': request.form['interface'],
            'address-pool': request.form['pool']
        })
        return redirect(url_for('list_dhcp_server')) 
    except Exception as e:
        return f"DHCP Update Error: {str(e)}"

###########################  DHCP Setup ##############################

@app.route('/mikrotik/networks/dhcp-server/setup', methods=['POST'])
def dhcp_setup_mikrotik():
    if 'target_ip' not in session: return redirect('/')
    try:
        api = connect_to_mikrotik()
        interface = request.form['interface']
        ip_range = request.form['ip_range']
        gateway = request.form['gateway']
        dns = request.form['dns']
        
        pool_name = f"pool_{interface}"
        existing_pools = list(api.path('/ip/pool').select())
        pool_data = next((p for p in existing_pools if p['name'] == pool_name), None)
        
        if not pool_data:
            api.path('/ip/pool').add(name=pool_name, ranges=ip_range)
        else:
            api.path('/ip/pool').update(**{'.id': pool_data['.id'], 'ranges': ip_range})
        subnet = f"{gateway.rsplit('.', 1)[0]}.0/24"
        existing_nets = list(api.path('/ip/dhcp-server/network').select())
        net_exists = any(n['address'] == subnet for n in existing_nets)
        
        if not net_exists:
            api.path('/ip/dhcp-server/network').add(**{
                'address': subnet,
                'gateway': gateway,
                'dns-server': dns
            })
        api.path('/ip/dhcp-server').add(**{
            'name': f"dhcp_{interface}",
            'interface': interface,
            'address-pool': pool_name,
            'disabled': 'no'
        })
        
        return redirect(url_for('list_dhcp_server'))
    except Exception as e:
        if "already exists" in str(e):
            return redirect(url_for('list_dhcp_server'))
        return f"DHCP Setup Error: {str(e)}"




###########################DHCP LEASES############################
@app.route('/mikrotik/networks/dhcp-leases')
def list_dhcp_leases():
    if 'target_ip' not in session: return redirect('/')
    try:
        api = connect_to_mikrotik()
        leases = list(api.path('/ip/dhcp-server/lease').select())
        return render_template('mikrotik_dhcp_lease.html', leases=leases)
    except Exception as e:
        return f"Lease Load Error: {str(e)}"

########################### Lease Create #####################
@app.route('/mikrotik/networks/dhcp-leases/make-static', methods=['POST'])
def make_lease_static():
    if 'target_ip' not in session: return redirect('/')
    try:
        api = connect_to_mikrotik()
        api.path('/ip/dhcp-server/lease').add(**{
            'address': request.form['address'],
            'mac-address': request.form['mac'],
            'server': request.form['server'],
            'comment': 'Static via Web Panel'
        })
        return redirect(url_for('list_dhcp_leases'))
    except Exception as e:
        return f"Static Lease Error: {str(e)}"

########################### Lease DELETE #####################

@app.route('/mikrotik/networks/dhcp-leases/delete/<id>')
def delete_lease(id):
    if 'target_ip' not in session: return redirect('/')
    try:
        api = connect_to_mikrotik()
        api.path('/ip/dhcp-server/lease').remove(id)
        return redirect(url_for('list_dhcp_leases'))
    except Exception as e:
        return f"Delete Error: {str(e)}"

############################ LEASE EDIT #########################

@app.route('/mikrotik/networks/dhcp-leases/edit', methods=['POST'])
def edit_lease():
    if 'target_ip' not in session: return redirect('/')
    try:
        api = connect_to_mikrotik()
        lease_id = request.form['lease_id']
        try:
            api.path('/ip/dhcp-server/lease').call('make-static', {'.id': lease_id})
        except:
            pass

        # ডাটা আপডেট করা
        api.path('/ip/dhcp-server/lease').update(**{
            '.id': lease_id,
            'address': request.form['address'],
            'mac-address': request.form['mac'],
            'server': request.form['server'],
            'comment': request.form['comment']
        })
        
        return redirect(url_for('list_dhcp_leases'))
    except Exception as e:
        return f"Lease Update Error: {str(e)}"

###################FIREWALL###############

@app.route('/mikrotik/firewall')
def firewall_page():
    if 'target_ip' not in session: return redirect('/')
    
    api = connect(host=session['target_ip'], username=session['target_user'], password=session['target_pass'])
    addresses = list(api.path('/ip/firewall/address-list').select())
    nat_rules = list(api.path('/ip/firewall/nat').select())
    return render_template('mikrotik_firewall.html', 
                           addresses=addresses, 
                           nat_rules=nat_rules)

# ################ mikrotik firewall block ip add ###########################
@app.route('/mikrotik/firewall/add', methods=['POST'])
def add_ip():
    ip = request.form.get('ip')
    list_name = request.form.get('list_name')
    api = connect(host=session['target_ip'], username=session['target_user'], password=session['target_pass'])
    api.path('/ip/firewall/address-list').add(address=ip, list=list_name)
    return redirect(url_for('firewall_page'))

# ################ mikrotik firewall block ip delete ###########################
@app.route('/mikrotik/firewall/remove', methods=['POST'])
def remove_ip():
    addr_id = request.form.get('id')
    api = connect(host=session['target_ip'], username=session['target_user'], password=session['target_pass'])
    api.path('/ip/firewall/address-list').remove(addr_id)
    return redirect(url_for('firewall_page'))



############################### NAT ###############################
@app.route('/mikrotik/firewall/nat')
def nat_page():
    if 'target_ip' not in session: return redirect('/')
    try:
        api = connect(host=session['target_ip'], username=session['target_user'], password=session['target_pass'])
        nat_rules = list(api.path('/ip/firewall/nat').select())
        return render_template('mikrotik_nat.html', nat_rules=nat_rules)
    except Exception as e:
        print(f"NAT Fetch Error: {e}")
        return f"Error loading NAT: {e}"

# ################ NAT IP ADD ###########################
@app.route('/mikrotik/firewall/nat/add', methods=['POST'])
def add_nat():
    chain = request.form.get('chain')
    out_iface = request.form.get('out_interface')
    action = request.form.get('action')
    api = connect(host=session['target_ip'], username=session['target_user'], password=session['target_pass'])
    api.path('/ip/firewall/nat').add(chain=chain, **{"out-interface": out_iface}, action=action)
    
    return redirect(url_for('firewall_page'))

# ################ mikrotik firewall nat remove ###########################
@app.route('/mikrotik/firewall/nat/remove', methods=['POST'])
def remove_nat():
    rule_id = request.form.get('id')
    api = connect(host=session['target_ip'], username=session['target_user'], password=session['target_pass'])
    api.path('/ip/firewall/nat').remove(rule_id)
    return redirect(url_for('nat_page'))


########################## LOG OUT ##########################
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
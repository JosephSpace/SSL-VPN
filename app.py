from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from auth import ADAuth
from config import Config
import os
import sys
from functools import wraps
from datetime import datetime
import ctypes  # Yönetici kontrolü için

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Yönetici olarak çalışıp çalışmadığını kontrol eden fonksiyon
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False  # Windows dışı sistemlerde False döner

app = Flask(__name__, 
          static_url_path='',
          static_folder='.',
          template_folder='.')

app.secret_key = os.urandom(24)

@app.route('/')
def index():
    if 'username' not in session:
        return render_template('templates/index.html')
    return redirect(url_for('home'))

@app.route('/home')
@login_required
def home():
    return render_template('templates/home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Geçici hesap kontrolü
        if username == Config.TEMP_USERNAME and password == Config.TEMP_PASSWORD:
            session['username'] = username
            session['is_temp_account'] = True
            return redirect(url_for('home'))
        
        # AD sunucu bilgilerini yapılandırmadan alın
        ad_auth = ADAuth(Config.AD_SERVER, Config.AD_SEARCH_BASE.split(',')[0].replace('DC=', ''))
        
        # AD kimlik doğrulaması
        conn = ad_auth.connect()
        if not conn:
            return render_template('templates/index.html', error='AD sunucusuna bağlanılamadı')
            
        try:
            # Kullanıcı kimlik doğrulaması
            if conn.bind(user=f"{username}@{Config.AD_DOMAIN}", password=password):
                session['username'] = username
                session['is_temp_account'] = False
                return redirect(url_for('home'))
            else:
                return render_template('templates/index.html', error='Geçersiz kullanıcı adı veya şifre')
        except Exception as e:
            return render_template('templates/index.html', error=str(e))
        finally:
            conn.unbind()
            
    return render_template('templates/index.html')

@app.route('/userlog', methods=['GET', 'POST'])
@login_required
def userlog():
    if request.method == 'POST':
        try:
            username = request.form.get('aduser')
            start_date = request.form.get('startdate')
            finish_date = request.form.get('finishdate')
            ad_server = request.form.get('ad_server')
            domain = request.form.get('domain')

            if not all([username, start_date, finish_date, ad_server, domain]):
                return render_template('templates/userlog.html', error='Tüm alanları doldurun')

            ad_auth = ADAuth(ad_server, domain)
            computer_info = ad_auth.get_user_computer_info(username, start_date, finish_date)

            if computer_info is None:
                return render_template('templates/userlog.html', error='Kullanıcı bilgileri alınamadı')

            return render_template('templates/userlog.html', results=computer_info)
        except Exception as e:
            return render_template('templates/userlog.html', error=str(e))

    return render_template('templates/userlog.html')

@app.route('/personel', methods=['GET', 'POST'])
@login_required
def p_list():
    # AD bağlantısı oluştur
    ad_auth = ADAuth(Config.AD_SERVER, Config.AD_DOMAIN)
    conn = ad_auth.connect()
    
    if not conn:
        return render_template('templates/P-list.html', error='AD sunucusuna bağlanılamadı')
    
    # Arama işlemi
    search_term = request.args.get('search', '')
    
    # Kullanıcı ekleme işlemi
    if request.method == 'POST':
        try:
            aduser = request.form.get('aduser')
            sicil = request.form.get('sicil')
            ad = request.form.get('ad')
            soyad = request.form.get('soyad')
            birim = request.form.get('birim')
            
            if not all([aduser, sicil, ad, soyad, birim]):
                return render_template('templates/P-list.html', error='Tüm alanları doldurun')
            
            # Active Directory'ye kullanıcı ekle
            success, message = ad_auth.add_user(aduser, sicil, ad, soyad, birim)
            
            if success:
                users = ad_auth.get_all_users()
                return render_template('templates/P-list.html', success=message, users=users)
            else:
                users = ad_auth.get_all_users()
                return render_template('templates/P-list.html', error=message, users=users)
        except Exception as e:
            users = ad_auth.get_all_users()
            return render_template('templates/P-list.html', error=str(e), users=users)
        finally:
            conn.unbind()
    
    # Kullanıcıları listele (arama terimine göre veya tümünü)
    try:
        if search_term:
            users = ad_auth.search_users(search_term)
        else:
            users = ad_auth.get_all_users()
        return render_template('templates/P-list.html', users=users, search_term=search_term)
    except Exception as e:
        return render_template('templates/P-list.html', error=str(e))
    finally:
        conn.unbind()

@app.route('/log', methods=['GET', 'POST'])
@login_required
def dc_log():
    if request.method == 'POST':
        try:
            pcname = request.form.get('pcname')
            start_date = request.form.get('startdate')
            finish_date = request.form.get('finishdate')
            
            if not all([pcname, start_date, finish_date]):
                return render_template('templates/dc-log.html', error='Tüm alanları doldurun')
            
            # AD bağlantısı oluştur
            ad_auth = ADAuth(Config.AD_SERVER, Config.AD_DOMAIN)
            conn = ad_auth.connect()
            
            if not conn:
                return render_template('templates/dc-log.html', error='AD sunucusuna bağlanılamadı')
            
            try:
                # Bilgisayar bilgilerini ara
                computer_filter = f'(&(objectClass=computer)(cn={pcname}))'
                conn.search(Config.AD_SEARCH_BASE, computer_filter, 
                          attributes=['lastLogon', 'lastLogoff', 'operatingSystem', 'logonCount'])
                
                if not conn.entries:
                    return render_template('templates/dc-log.html', error=f'{pcname} bilgisayarı bulunamadı')
                
                # Bilgisayar bilgilerini al
                comp = conn.entries[0]
                last_logon = datetime.fromtimestamp(int(comp.lastLogon.value) / 10000000 - 11644473600)
                
                # Bilgisayara giriş yapan kullanıcıları bul
                user_filter = f'(&(objectClass=user)(objectCategory=person))'
                conn.search(Config.AD_SEARCH_BASE, user_filter, 
                          attributes=['sAMAccountName', 'userWorkstations', 'lastLogon'])
                
                computer_logs = []
                for user in conn.entries:
                    # Kullanıcının bilgisayarlarını kontrol et
                    if hasattr(user, 'userWorkstations') and user.userWorkstations.value:
                        workstations = user.userWorkstations.value.split(',')
                        if pcname in workstations:
                            user_last_logon = datetime.fromtimestamp(int(user.lastLogon.value) / 10000000 - 11644473600)
                            # Tarih aralığını kontrol et
                            start = datetime.strptime(start_date, '%Y-%m-%d')
                            end = datetime.strptime(finish_date, '%Y-%m-%d')
                            
                            if start <= user_last_logon <= end:
                                # Bilgisayarın şu anki durumunu kontrol et
                                is_online = (last_logon > datetime.now().replace(hour=0, minute=0, second=0, microsecond=0))
                                status = "Açık" if is_online else "Kapalı"
                                
                                computer_logs.append({
                                    'aduser': user.sAMAccountName.value,
                                    'computer_name': pcname,
                                    'status': status,
                                    'last_logon': user_last_logon.strftime('%Y-%m-%d %H:%M:%S')
                                })
                
                return render_template('templates/dc-log.html', results=computer_logs)
            except Exception as e:
                return render_template('templates/dc-log.html', error=str(e))
            finally:
                conn.unbind()
        except Exception as e:
            return render_template('templates/dc-log.html', error=str(e))
    
    return render_template('templates/dc-log.html')

@app.route('/password', methods=['GET', 'POST'])
def passwd():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password1 = request.form.get('new_password1')
        new_password2 = request.form.get('new_password2')

        if not all([old_password, new_password1, new_password2]):
            return render_template('templates/passwd.html', error='Tüm alanları doldurun')

        if new_password1 != new_password2:
            return render_template('templates/passwd.html', error='Yeni şifreler eşleşmiyor')

        # AD sunucu bilgilerini yapılandırmadan alın
        ad_auth = ADAuth(Config.AD_SERVER, Config.AD_DOMAIN)
        success, message = ad_auth.change_password(session['username'], old_password, new_password1)

        if success:
            return render_template('templates/passwd.html', success=message)
        else:
            return render_template('templates/passwd.html', error=message)

    return render_template('templates/passwd.html')

@app.route('/search')
@login_required
def search():
    return render_template('templates/search.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Uygulamayı çalıştırma fonksiyonu
def run_app():
    print(f"Uygulama {'yönetici' if is_admin() else 'normal kullanıcı'} olarak çalışıyor.")
    app.run(host='192.168.1.121', port=3030, debug=True)

if __name__ == '__main__':
    # Yönetici olarak çalıştırılmak istenirse
    if len(sys.argv) > 1 and sys.argv[1] == '--admin':
        if not is_admin():
            # Yönetici haklarıyla yeniden başlat
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join([__file__, '--admin']), None, 1)
            sys.exit(0)
        else:
            run_app()
    else:
        # Normal kullanıcı olarak çalıştır
        run_app()
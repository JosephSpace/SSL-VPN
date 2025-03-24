from ldap3 import Server, Connection, ALL, NTLM
from datetime import datetime
from config import Config

class ADAuth:
    def __init__(self, server_ip, domain):
        Config.init_ad_config(server_ip, domain)
        self.server = Server(Config.AD_SERVER, port=Config.AD_PORT, get_info=ALL)
        self.domain = domain

    def connect(self):
        try:
            # Kimlik bilgileri varsa kullan
            if Config.AD_BIND_USER and Config.AD_BIND_PASSWORD:
                conn = Connection(self.server,
                                user=f"{self.domain}\\{Config.AD_BIND_USER}",
                                password=Config.AD_BIND_PASSWORD,
                                authentication=NTLM,
                                auto_bind=True)
            else:
                # Anonim bağlantı
                conn = Connection(self.server, auto_bind=True)
            return conn
        except Exception as e:
            print(f"AD Bağlantı Hatası: {str(e)}")
            return None
            
    def check_admin_access(self, username, password):
        try:
            # Kullanıcı kimlik doğrulaması
            conn = Connection(self.server,
                            user=f"{username}@{self.domain}",
                            password=password,
                            authentication=NTLM)
            if not conn.bind():
                return False, "Geçersiz kullanıcı adı veya şifre"

            # Admin grup üyeliğini kontrol et
            search_filter = f'(&(objectClass=user)(sAMAccountName={username})(memberOf=CN=Domain Admins,CN=Users,{Config.AD_SEARCH_BASE}))'
            conn.search(Config.AD_SEARCH_BASE, search_filter, attributes=['memberOf'])
            
            if not conn.entries:
                return False, "Bu sayfaya erişim yetkiniz yok"
                
            return True, "Giriş başarılı"
        except Exception as e:
            return False, str(e)
        finally:
            if conn:
                conn.unbind()

    def change_password(self, username, old_password, new_password):
        try:
            # Şifre politikası kontrolleri
            if len(new_password) < 8:
                return False, "Şifre en az 8 karakter olmalıdır"
            
            if new_password.isdigit():
                return False, "Şifre sadece sayısal karakterlerden oluşamaz"
            
            # Yaygın şifreleri kontrol et
            common_passwords = ["password", "123456", "qwerty", "admin"]
            if new_password.lower() in common_passwords:
                return False, "Bu şifre yaygın olarak kullanılmaktadır"
            
            # Kişisel bilgilerle benzerlik kontrolü
            if username.lower() in new_password.lower():
                return False, "Şifre kullanıcı adınızla benzer olamaz"

            # Önce eski şifre ile bağlantı kontrolü
            conn = Connection(self.server,
                            user=f"{username}@{self.domain}",
                            password=old_password,
                            authentication=NTLM)
            if not conn.bind():
                return False, "Mevcut şifre yanlış"

            # Şifre değiştirme işlemi
            conn.extend.microsoft.modify_password(user=f"{username}@{self.domain}",
                                                new_password=new_password)
            return True, "Şifre başarıyla değiştirildi"
        except Exception as e:
            return False, str(e)

    def get_user_computer_info(self, username, start_date, end_date):
        conn = self.connect()
        if not conn:
            return None

        try:
            # Kullanıcının bilgisayarını bul
            search_filter = f'(&(objectClass=user)(sAMAccountName={username}))'
            conn.search(Config.AD_SEARCH_BASE, search_filter, attributes=['userWorkstations'])
            
            if not conn.entries:
                return None

            computer_names = conn.entries[0].userWorkstations.value
            if not computer_names:
                return None
                
            computer_info = []
            for computer in computer_names.split(','):
                # Bilgisayar durumunu kontrol et
                computer_filter = f'(&(objectClass=computer)(cn={computer}))'
                conn.search(Config.AD_SEARCH_BASE, computer_filter, 
                          attributes=['lastLogon', 'lastLogoff', 'pwdLastSet', 'operatingSystem'])
                
                if conn.entries:
                    comp = conn.entries[0]
                    last_logon = datetime.fromtimestamp(int(comp.lastLogon.value) / 10000000 - 11644473600)
                    last_logoff = datetime.fromtimestamp(int(comp.lastLogoff.value) / 10000000 - 11644473600)
                    
                    # Bilgisayarın şu anki durumunu kontrol et
                    is_online = (last_logon > last_logoff)
                    status = "Açık" if is_online else "Kapalı"
                    
                    computer_info.append({
                        'computer_name': computer,
                        'status': status,
                        'last_logon': last_logon.strftime('%Y-%m-%d %H:%M:%S'),
                        'last_logoff': last_logoff.strftime('%Y-%m-%d %H:%M:%S')
                    })

            return computer_info
                
        except Exception as e:
            print(f"Kullanıcı bilgisayar bilgisi alınırken hata: {str(e)}")
            return None
        finally:
            conn.unbind()
                
    def add_user(self, aduser, sicil, ad, soyad, birim):
        """
        Active Directory'ye yeni kullanıcı ekler
        """
        conn = self.connect()
        if not conn:
            return False, "AD sunucusuna bağlanılamadı"
            
        try:
            # Kullanıcının zaten var olup olmadığını kontrol et
            search_filter = f'(&(objectClass=user)(sAMAccountName={aduser}))'
            conn.search(Config.AD_SEARCH_BASE, search_filter, attributes=['cn'])
            
            if conn.entries:
                return False, f"{aduser} kullanıcı adı zaten kullanımda"
                
            # Yeni kullanıcı oluştur
            user_dn = f"CN={ad} {soyad},OU=Users,{Config.AD_SEARCH_BASE}"
            
            # Kullanıcı özellikleri
            attributes = {
                'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
                'cn': f"{ad} {soyad}",
                'sAMAccountName': aduser,
                'givenName': ad,
                'sn': soyad,
                'displayName': f"{ad} {soyad}",
                'department': birim,
                'employeeID': sicil,
                'userAccountControl': '512'  # Normal hesap
            }
            
            # Kullanıcıyı ekle
            conn.add(user_dn, attributes=attributes)
            
            if conn.result['result'] == 0:
                # Varsayılan şifre ayarla (kullanıcı ilk girişte değiştirmeli)
                initial_password = f"Welcome{sicil}!"
                conn.extend.microsoft.modify_password(user_dn, initial_password, None)
                
                # Kullanıcının şifreyi ilk girişte değiştirmesini zorunlu kıl
                conn.modify(user_dn, {'pwdLastSet': [(conn.MODIFY_REPLACE, [0])]})  
                
                return True, f"{ad} {soyad} kullanıcısı başarıyla eklendi"
            else:
                return False, f"Kullanıcı eklenirken hata oluştu: {conn.result['description']}"
                
        except Exception as e:
            return False, f"Kullanıcı eklenirken hata oluştu: {str(e)}"
        finally:
            conn.unbind()
            
    def get_all_users(self):
        """
        Active Directory'deki tüm kullanıcıları listeler
        """
        conn = self.connect()
        if not conn:
            return None
            
        try:
            # Tüm kullanıcıları ara
            search_filter = '(&(objectClass=user)(objectCategory=person))'
            conn.search(Config.AD_SEARCH_BASE, search_filter, 
                      attributes=['sAMAccountName', 'givenName', 'sn', 'department', 'employeeID'])
            
            users = []
            for entry in conn.entries:
                user = {
                    'aduser': entry.sAMAccountName.value if hasattr(entry, 'sAMAccountName') else '',
                    'sicil': entry.employeeID.value if hasattr(entry, 'employeeID') else '',
                    'ad': entry.givenName.value if hasattr(entry, 'givenName') else '',
                    'soyad': entry.sn.value if hasattr(entry, 'sn') else '',
                    'birim': entry.department.value if hasattr(entry, 'department') else ''
                }
                users.append(user)
                
            return users
        except Exception as e:
            print(f"Kullanıcılar listelenirken hata oluştu: {str(e)}")
            return None
        finally:
            conn.unbind()
            
    def search_users(self, search_term):
        """
        Active Directory'de belirli bir terime göre kullanıcı araması yapar
        """
        conn = self.connect()
        if not conn:
            return None
            
        try:
            # Arama terimini içeren kullanıcıları ara
            search_filter = f'(&(objectClass=user)(objectCategory=person)(|(sAMAccountName=*{search_term}*)(givenName=*{search_term}*)(sn=*{search_term}*)(department=*{search_term}*)(employeeID=*{search_term}*)))'
            conn.search(Config.AD_SEARCH_BASE, search_filter, 
                      attributes=['sAMAccountName', 'givenName', 'sn', 'department', 'employeeID'])
            
            users = []
            for entry in conn.entries:
                user = {
                    'aduser': entry.sAMAccountName.value if hasattr(entry, 'sAMAccountName') else '',
                    'sicil': entry.employeeID.value if hasattr(entry, 'employeeID') else '',
                    'ad': entry.givenName.value if hasattr(entry, 'givenName') else '',
                    'soyad': entry.sn.value if hasattr(entry, 'sn') else '',
                    'birim': entry.department.value if hasattr(entry, 'department') else ''
                }
                users.append(user)
                
            return users
        except Exception as e:
            print(f"Kullanıcı araması yapılırken hata oluştu: {str(e)}")
            return None
        finally:
            conn.unbind()
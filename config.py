# Active Directory Configuration
class Config:
    # AD server configuration
    AD_SERVER = "192.168.1.100"  # Sabit LDAP sunucu IP adresi
    AD_PORT = 389  # Default LDAP port
    AD_USE_SSL = False
    AD_SEARCH_BASE = "DC=domain,DC=local"  # Sabit domain yapılandırması
    AD_DOMAIN = "domain.local"  # AD domain adı
    AD_BIND_USER = None
    AD_BIND_PASSWORD = None
    
    # Geçici hesap bilgileri
    TEMP_USERNAME = "admin"
    TEMP_PASSWORD = "123"
    
    @classmethod
    def init_ad_config(cls, server_ip, domain, bind_user=None, bind_password=None):
        cls.AD_SERVER = server_ip
        # Convert domain to LDAP search base format (e.g., DC=example,DC=com)
        cls.AD_SEARCH_BASE = ','.join([f'DC={dc}' for dc in domain.split('.')])
        cls.AD_BIND_USER = bind_user
        cls.AD_BIND_PASSWORD = bind_password
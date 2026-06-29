# QUICKSTART — patroni-kurulum

Tek sayfalık operatör başlangıç rehberi. Tüm komutlar `patroni-kurulum/`
dizininden çalıştırılır.

> Ön koşul: kontrol düğümünde `ansible-core`, `python3` ve `sshpass` kurulu;
> hedef sunucular açık, OS kurulu, diskler mount edilmiş (prebuilt mod).

---

## 1. Envanteri düzenle

`inventory/infra.yml` — **tek envanter**, patroni + haproxy gruplarını birleştirir.
Ansible varsayılan olarak bu dosyayı kullanır (`ansible.cfg: inventory = inventory/infra.yml`).

Düzenlenecek alanlar:
- `patroni` grubu: her düğüm için `ansible_host`, `ansible_password`, `node_name`, `node_public_ip`, `node_cluster_ip`
- `haproxy` grubu: her düğüm için `ansible_host`, `ansible_password`, `keepalived_state` (MASTER/BACKUP), `keepalived_priority`
- `node_name`, `inventory/group_vars/all/vars.yml` içindeki `nodes[].name` ile birebir aynı olmalı (etcd initial-cluster).

## 2. Değişkenleri düzenle

`inventory/group_vars/all/vars.yml`:
- `vm_arch`: `x86_64` veya `aarch64`
- `nodes`: isim/IP/MAC üçlüsü (inventory ile tutarlı)
- `networks`: public ve cluster subnet/gateway
- `postgres_version`: 14/15/16/17
- `haproxy_vip`, `keepalived_vrid`: VIP ve ağda benzersiz VRID
- portlar (haproxy_*_port, pgbouncer_*_port) ve PgBouncer havuz ayarları

## 3. Vault parolalarını ayarla

```bash
$EDITOR inventory/group_vars/all/vault.yml      # değerleri değiştir
echo 'GüçlüVaultParolası' > .vault_pass
chmod 0400 .vault_pass
ansible-vault encrypt inventory/group_vars/all/vault.yml
```

## 4. Koleksiyonları kur

```bash
ansible-galaxy collection install -r requirements.yml
dnf install -y sshpass     # parola tabanlı SSH için (gerekiyorsa)
```

Bağlantıyı doğrula:

```bash
ansible all -m ping
```

## 5. Patroni kur

```bash
ansible-playbook playbooks/01-patroni.yml
# Doğrulama: reports/patroni-kurulum-*.html
```

## 6. HAProxy / Keepalived / PgBouncer kur

```bash
ansible-playbook playbooks/02-haproxy.yml
# Doğrulama: reports/haproxy-kurulum-*.html
```

## 7. Güvenlik sertleştirme uygula (seri reboot içerir)

```bash
ansible-playbook playbooks/03-security.yml
# Yavaş donanım: -e sec_reboot_timeout=600 -e sec_reboot_stabilize=60
# Çıktı: reports/security-report-*.html
```

## 8. PCP performans izleme (opsiyonel ama önerilir)

```bash
ansible-playbook playbooks/04-pcp-setup.yml
```

## 9. Performans testi (pgbench)

```bash
ansible-playbook playbooks/05-db-test.yml \
  -e db_test_scale=200 -e db_test_duration=120
# Çıktı: reports/db-test-report-*.html
```

## 10. Sağlık raporu al

```bash
ansible-playbook playbooks/06-health-report.yml
# Çıktı: reports/infra-health-*.html  ve  .txt
```

---

## Tek komutla tam kurulum

```bash
ansible-playbook playbooks/patroni-infra-kur.yml
```

Belirli adımı çalıştır:

```bash
ansible-playbook playbooks/patroni-infra-kur.yml --tags haproxy
ansible-playbook playbooks/patroni-infra-kur.yml --tags patroni,haproxy
```

## Hızlı doğrulama

```bash
# Küme durumu (bir patroni düğümünde)
ssh root@10.253.10.51 'patronictl -c /etc/patroni/patroni.yml list'

# VIP yazma testi
psql -h 10.253.10.56 -p 6432 -U postgres -c 'select pg_is_in_recovery();'
# → f (false = Primary)

# VIP okuma testi
psql -h 10.253.10.56 -p 6433 -U postgres -c 'select pg_is_in_recovery();'
# → t (true = Replica)

# HAProxy stats paneli
curl -s http://10.253.10.56:7000/

# etcd sağlık
ssh root@10.253.10.51 'ETCDCTL_API=3 etcdctl \
  --endpoints=http://10.255.255.51:2379,http://10.255.255.52:2379,http://10.255.255.53:2379 \
  endpoint health'

# PG 18 özelliklerini doğrula
psql -h 10.253.10.56 -p 6432 -U postgres \
  -c "SHOW io_method; SHOW wal_compression; SHOW huge_pages;"
```

---

## Kurulum sonrası kontrol listesi

```
[ ] pt-list     → 1 Leader (running) + 2 Replica (streaming), aynı TL, Lag=0
[ ] etcd-health → 3/3 sağlıklı
[ ] ha-backends → pg_primary UP, pg_replicas UP
[ ] kl-vip      → VIP aktif (10.253.10.56)
[ ] pb-pools    → cl_waiting = 0
[ ] SHOW io_method      → io_uring
[ ] SHOW wal_compression→ lz4
[ ] HugePages_Free > 0  → grep HugePages /proc/meminfo
[ ] Güvenlik raporu     → reports/security-report-*.html → 0 AVC
[ ] Sağlık raporu       → reports/infra-health-*.html → tüm yeşil
[ ] Vault parolaları üretim değerleriyle güncellensin
[ ] SSH parola auth kapatılsın (PasswordAuthentication no)
[ ] TLS yapılandırılsın (etcd + Patroni REST API + PG)
```

---

## Sık Karşılaşılan Hatalar

| Hata | Neden | Çözüm |
|------|-------|-------|
| `node_name is defined` assert | inventory'de `node_name` eksik | `infra.yml`'de her host'a ekle |
| `Connection refused` port 5432 | VM başlamadı veya Patroni çalışmıyor | `systemctl start patroni` |
| `etcd cluster not healthy` | Cluster ağı (10.255.255.x) sorunlu | `ping -I enp10s0 10.255.255.52` |
| `HAProxy 503 Backend` | Patroni henüz leader seçmedi | `pt-list` ile bekle |
| `rc: 137` (Ansible OOM) | user.slice MemoryMax çok düşük | `user_slice_memory_max: "2G"` |
| `io_uring not supported` | Kernel < 5.1 veya SELinux | `pg_io_method: "worker"` |
| `huge_pages başlamıyor` | nr_hugepages yetersiz | `pg_huge_pages: "try"` veya pg_tune çalıştır |
| `sshpass not found` | sshpass kurulu değil | `dnf install -y sshpass` |

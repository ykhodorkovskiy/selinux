# Installation directories.
PREFIX ?= ${DESTDIR}/usr
SYSCONFDIR ?= ${DESTDIR}/etc
BINDIR ?= $(PREFIX)/bin
SHAREDIR ?= $(PREFIX)/share/system-config-selinux
DATADIR ?= $(PREFIX)/share
PAMDIR ?= $(SYSCONFDIR)/etc/pam.d

TARGETS= \
booleansPage.py \
domainsPage.py \
fcontextPage.py \
html_util.py \
loginsPage.py \
mappingsPage.py \
modulesPage.py \
polgen.glade \
portsPage.py \
semanagePage.py \
statusPage.py \
system-config-selinux.glade \
system-config-selinux.pam \
system-config-selinux.png \
usersPage.py

all: $(TARGETS) system-config-selinux.py polgengui.py

install: all
	-mkdir -p $(SHAREDIR)
	-mkdir -p $(BINDIR)
	-mkdir -p $(DATADIR)/pixmaps
	-mkdir -p $(DATADIR)/icons/hicolor/24x24/apps
	-mkdir -p $(SYSCONFDIR)
	-mkdir -p $(PAMDIR)
	-mkdir -p $(SYSCONFDIR)/security/console.apps/system-config-selinux
	install -m 755 system-config-selinux.py $(SHAREDIR)
	install -m 755 polgengui.py $(SHAREDIR)
	install -m 755 sepolgen $(BINDIR)
	install -m 644 $(TARGETS) $(SHAREDIR)
	install -m 644 system-config-selinux.png $(DATADIR)/pixmaps
	install -m 644 system-config-selinux.png $(DATADIR)/icons/hicolor/24x24/apps
	install -m 644 system-config-selinux.png $(DATADIR)/system-config-selinux
	install -m 644 system-config-selinux.pam $(PAMDIR)/system-config-selinux
	install -m 644 system-config-selinux.console $(SYSCONFDIR)/security/console.apps/system-config-selinux

clean:

indent:

relabel:

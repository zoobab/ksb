/*****************************************************************************/
/* Kernel SOCKS Bouncer (Loadable Kernel Module) for 2.6.x kernels [KSB26]   */
/* (c) 2004-2005 Paolo Ardoino <ardoino.gnu@disi.unige.it>                   */
/*****************************************************************************/
/*									     */
/* This program is free software; you can redistribute it and/or modify	     */
/* it under the terms of the GNU General Public License as published by	     */
/* the Free Software Foundation; either version 2 of the License, or	     */
/* (at your option) any later version.					     */
/* This program is distributed in the hope that it will be useful,	     */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of	     */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the	     */
/* GNU General Public License for more details.				     */
/*									     */
/* You should have received a copy of the GNU General Public License	     */
/* along with this program; if not, write to the Free Software		     */
/* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA */
/*****************************************************************************/

static void ksb26_list_add(struct ksb26_host *new, struct ksb26_host *prev, struct ksb26_host *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static void ksb26_list_add_tail(struct ksb26_host *new, struct ksb26_host *head)
{
	ksb26_list_add(new, head->prev, head);
}

static void ksb26_list_del(struct ksb26_host *prev, struct ksb26_host *next)
{	
	next->prev = prev;
	prev->next = next;
}

int host_isin_list(char *ip, int port, struct ksb26_host *hl)
{
	struct ksb26_host *hlptr;
	
	for(hlptr = hl->next; hlptr != hl; hlptr = hlptr->next)
		if(strcmp(ip, hlptr->ip) == 0 && port == hlptr->port)
			return 1;
	return 0;
}

static int ksb26_add_socks(char *line)
{
	char *portbuf = NULL;
	char *ipbuf = NULL;
	int ipc;
	int port = 0, type = 0;
	struct ksb26_host *ksb26_haux = NULL;
	
	if(ksb26_isline2ch(line, ':', ';') != 1 || ksb26_isline2ch(line, 'S', ':') != 1)
		return 0;
	if(ksb26_getline(line, ':', ';', &portbuf) == 0)
		return 0;
	port = ksb26_atoi(portbuf);
	kfree(portbuf);
	if(ksb26_getline(line, 'S', ':', &ipbuf) == 0)
		return 0;
	if(ksb26_isip(ipbuf) == 0 || ksb26_istcpport(port) == 0) {
		kfree(ipbuf);
		return 0;
	}
	type = ksb26_atoi((strchr(line, ';') + 1));
	if(type != 4 && type != 5) 
		return 0;
	if(host_isin_list(ipbuf, port, &ksb26_slh) == 1)
		return 0;
	ksb26_haux = kmalloc(sizeof(struct ksb26_host), GFP_KERNEL);
	ksb26_list_add_tail(ksb26_haux, &ksb26_slh);
	strncpy(ksb26_slh.prev->ip, ipbuf, 18);
	ksb26_slh.prev->port = port;
	ksb26_slh.prev->naddr = in_aton(ksb26_slh.prev->ip);
	ksb26_slh.prev->nport = htons(ksb26_slh.prev->port);
	ksb26_slh.prev->wrk = 1;
	if(type == 4) {
		ipc = in_aton(ipbuf);
		memcpy(ksb26_slh.prev->ipc, &ipc, 4);
		ksb26_slh.prev->ipc[4] = '\0';
//		printk("socks4:%d.%d.%d.%d\n", ksb26_slh.prev->ipc[0], ksb26_slh.prev->ipc[1], ksb26_slh.prev->ipc[2], ksb26_slh.prev->ipc[3]);
	}
	ksb26_slh.prev->type = type;
	ksb26_nsocks++;
	kfree(ipbuf);
//	printk("%ld:%d\n", ksb26_slh.prev->naddr, ksb26_slh.prev->nport);
	printk("[%s] %s:%d SOCKS v%d added.\n", MODNAME, ksb26_slh.prev->ip, ksb26_slh.prev->port, ksb26_slh.prev->type);
	return 1;
}

static int ksb26_add_thost(char *line)
{
	char *ipbuf = NULL;
	char *portbuf = NULL;
	int port = 0;
	struct ksb26_host *ksb26_haux = NULL;
	
	if(ksb26_isline2ch(line, ':', ';') != 1 || ksb26_isline2ch(line, 'H', ':') != 1)
		return 0;
	if(ksb26_getline(line, ':', ';', &portbuf) == 0)
		return 0;
	port = ksb26_atoi(portbuf);
	kfree(portbuf);
	if(port < 0 || port > 65535)
		port = 0;
	if(ksb26_getline(line, 'H', ':', &ipbuf) == 0)	
		return 0;
	if(ksb26_isip(ipbuf) == 0 && ipbuf[0] != '*') {
		kfree(ipbuf);
		return 0;
	}
	if(host_isin_list(ipbuf, port, &ksb26_bhlh) == 1)
		return 0;
	ksb26_haux = kmalloc(sizeof(struct ksb26_host), GFP_KERNEL);
	ksb26_list_add_tail(ksb26_haux, &ksb26_bhlh);
	strncpy(ksb26_bhlh.prev->ip, ipbuf, 18);
	ksb26_bhlh.prev->port = port;
	ksb26_bhlh.prev->naddr = in_aton(ksb26_bhlh.prev->ip);
	ksb26_bhlh.prev->nport = htons(ksb26_bhlh.prev->port);
	kfree(ipbuf);
//	printk("%ld:%d\n", ksb26_bhlh.prev->naddr, ksb26_bhlh.prev->nport);
	printk("[%s] %s:%d target host added.\n", MODNAME, ksb26_bhlh.prev->ip, ksb26_bhlh.prev->port);
	return 1;
}

static void ksb26_clear_sockslist(void)
{
	struct ksb26_host *ksb26_haux = NULL;
	
	while((ksb26_haux = ksb26_slh.prev) != &ksb26_slh) {
		ksb26_nsocks++;
		ksb26_list_del(ksb26_haux->prev, &ksb26_slh);
		kfree(ksb26_haux);
	}
	ksb26_nsocks = 0;
}

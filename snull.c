#include <linux/module.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/kernel.h> /* printk() */
#include <linux/slab.h> /* kmalloc() */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/interrupt.h> /* mark_bh */
#include <linux/in.h>
#include <linux/netdevice.h>   /* struct device, and other headers */
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/ip.h>          /* struct iphdr */
#include <linux/tcp.h>         /* struct tcphdr */
#include <linux/skbuff.h>
#include "snull.h"
#include <linux/in6.h>
#include <asm/checksum.h>

MODULE_LICENSE("Dual BSD/GPL");

static int lockup = 0;
module_param(lockup, int, 0);

static int timeout = SNULL_TIMEOUT;
module_param(timeout, int, 0);

struct net_device *snull_devs[2];

struct snull_packet {
	struct snull_packet *next;
	struct net_device *dev;
	int	datalen;
	u8 data[ETH_DATA_LEN];
};

int pool_size = 8;
module_param(pool_size, int, 0);

struct snull_priv {
	struct net_device *dev;
	struct napi_struct napi;
	struct net_device_stats stats;
	int status;
	struct snull_packet *tx_queue;
	struct snull_packet *rx_queue;  /* List of incoming packets */
	int rx_int_enabled;
	int tx_packetlen;
	u8 *tx_packetdata;
	struct sk_buff *skb;
	spinlock_t lock;
};

static void snull_tx_timeout(struct net_device *dev)
{
	printk("timeout!\n");
}

void snull_setup_tx_queue(struct net_device *dev)
{
	struct snull_priv *priv = netdev_priv(dev);
	int i;
	struct snull_packet *pkt;

	priv->tx_queue = NULL;
	for (i = 0; i < pool_size; i++) {
		pkt = kmalloc (sizeof (struct snull_packet), GFP_KERNEL);
		if (pkt == NULL) {
			printk (KERN_NOTICE "Ran out of memory allocating packet pool\n");
			return;
		}
		pkt->dev = dev;
		pkt->next = priv->tx_queue;
		priv->tx_queue = pkt;
	}
}

void snull_teardown_tx_queue(struct net_device *dev)
{
	struct snull_priv *priv = netdev_priv(dev);
	struct snull_packet *pkt;
    
	while ((pkt = priv->tx_queue)) {
		priv->tx_queue = pkt->next;
		kfree (pkt);
		/* FIXME - in-flight packets ? */
	}
}

struct snull_packet *snull_get_tx(struct net_device *dev)
{
	struct snull_priv *priv = netdev_priv(dev);
	unsigned long flags;
	struct snull_packet *pkt;
    
	spin_lock_irqsave(&priv->lock, flags);
	pkt = priv->tx_queue;
	priv->tx_queue = pkt->next;
	if (priv->tx_queue == NULL) {
		printk (KERN_INFO "Pool empty\n");
		netif_stop_queue(dev);
	}
	spin_unlock_irqrestore(&priv->lock, flags);
	return pkt;
}

void snull_save_tx(struct snull_packet *pkt)
{
	unsigned long flags;
	struct snull_priv *priv = netdev_priv(pkt->dev);
	
	spin_lock_irqsave(&priv->lock, flags);
	pkt->next = priv->tx_queue;
	priv->tx_queue = pkt;
	spin_unlock_irqrestore(&priv->lock, flags);
	if (netif_queue_stopped(pkt->dev) && pkt->next == NULL)
		netif_wake_queue(pkt->dev);
}

void snull_save_rx(struct net_device *dev, struct snull_packet *pkt)
{
	unsigned long flags;
	struct snull_priv *priv = netdev_priv(dev);

	spin_lock_irqsave(&priv->lock, flags);
	pkt->next = priv->rx_queue;  /* FIXME - misorders packets */
	priv->rx_queue = pkt;
	spin_unlock_irqrestore(&priv->lock, flags);
}

struct snull_packet *snull_get_rx(struct net_device *dev)
{
	struct snull_priv *priv = netdev_priv(dev);
	struct snull_packet *pkt;
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);
	pkt = priv->rx_queue;
	if (pkt != NULL)
		priv->rx_queue = pkt->next;
	spin_unlock_irqrestore(&priv->lock, flags);
	return pkt;
}

static void snull_rx_ints(struct net_device *dev, int enable)
{
	struct snull_priv *priv = netdev_priv(dev);
	priv->rx_int_enabled = enable;
}

int snull_open(struct net_device *dev)
{
	memcpy(dev->dev_addr, "\0SNUL0", ETH_ALEN);
	if (dev == snull_devs[1])
		dev->dev_addr[ETH_ALEN-1]++; /* \0SNUL1 */
	netif_start_queue(dev);
	return 0;
}

int snull_release(struct net_device *dev)
{
    /* release ports, irq and such -- like fops->close */

	netif_stop_queue(dev); /* can't transmit any more */
	return 0;
}

int snull_config(struct net_device *dev, struct ifmap *map)
{
	if (dev->flags & IFF_UP) /* can't act on a running interface */
		return -EBUSY;
	/* Don't allow changing the I/O address */
	if (map->base_addr != dev->base_addr) {
		printk(KERN_WARNING "snull: Can't change I/O address\n");
		return -EOPNOTSUPP;
	}
	/* Allow changing the IRQ */
	if (map->irq != dev->irq) {
		dev->irq = map->irq;
        	/* request_irq() is delayed to open-time */
	}
	/* ignore other fields */
	return 0;
}

void snull_rx(struct net_device *dev, struct snull_packet *pkt)//接收数据
{
	struct snull_priv *priv = netdev_priv(dev);
	struct sk_buff *skb;
	skb = dev_alloc_skb(pkt->datalen + 2);//分配空间
	if(!skb){
		if(printk_ratelimit())//限制输出的长度
			printk("alloc skb failed!\n");
		priv->stats.rx_dropped++;
		goto out;
	}
	skb_reserve(skb,2);/*align IP on 16B boundary*/
	memcpy(skb_put(skb,pkt->datalen),pkt->data,pkt->datalen);
	skb->dev = dev;
	skb->protocol = eth_type_trans(skb,dev);
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	priv->stats.rx_packets++;
	priv->stats.rx_bytes += pkt->datalen;
	netif_rx(skb);//把skb交给内核处理
out:
	return;
}

static void snull_regular_interrupt(int irq, void *dev_id, struct pt_regs *regs)//中断的处理
{
	struct net_device *dev = (struct net_device *)dev_id;
	struct snull_packet *pkt = NULL;
	int statusword;
	if(NULL == dev)
		return;		
	struct snull_priv *priv = netdev_priv(dev);
	spin_lock(&priv->lock);//上锁操作防止抢资源
	statusword = priv->status;
	priv->status = 0;
	if(statusword & SNULL_RX_INTR){//是否接收操作
		pkt = priv->rx_queue;
		if(pkt){
			priv->rx_queue = pkt->next;//将指针移到下一项
			snull_rx(dev,pkt);		
		}		
	}
	if(statusword == SNULL_TX_INTR){//是否发送操作
		priv->stats.tx_packets++;//包的资源自增加
		priv->stats.tx_bytes += priv->tx_packetlen;
		dev_kfree_skb(priv->skb);//释放	
	}
	spin_unlock(&priv->lock);//解锁
	if(pkt) 
		snull_save_tx(pkt);
	return;
}
static void snull_hw_tx(char *buf, int len, struct net_device *dev)//发送数据
{
	struct iphdr *ih;
	struct net_device *dest;
	struct snull_priv *priv;
	u32 *saddr,*daddr;
	struct snull_packet *tx_buffer;
	if(len < sizeof(struct ethhdr) + sizeof(struct iphdr)){
		printk("packet too short (%i octets)",len);
		return;		
	}
	ih = (struct iphdr *)(buf + sizeof(struct ethhdr));
	saddr = &ih->saddr;
	daddr = &ih->daddr;
	((u8 *)saddr)[2] ^= 1;//异或操作判断最后一位
	((u8 *)daddr)[2] ^= 1;
	ih->check = 0;
	ih->check = ip_fast_csum((unsigned char *)ih,ih->ihl);
	dest = snull_devs[dev == snull_devs[0] ? 1 : 0];
	priv = netdev_priv(dest);
	tx_buffer = snull_get_tx(dev);
	tx_buffer->datalen = len;
	memcpy(tx_buffer->data,buf,len);
	snull_save_rx(dest,tx_buffer);
	if(priv->rx_int_enabled){
		priv->status |= SNULL_RX_INTR;//或上0x0001
		snull_regular_interrupt(0,dest,NULL);
	}
	priv = netdev_priv(dev);
	priv->tx_packetlen = len;
	priv->tx_packetdata = buf;
	priv->status |= SNULL_TX_INTR;//或上0x0002，去倒数两位
	if(lockup&&((priv->stats.tx_packets+1)%lockup) == 0){
		netif_stop_queue(dev);
		PDEBUGG("Simulate lockup at %ld,txp %ld\n",jiffies,(unsigned long)priv->stats.tx_packets);
	}
	else
		snull_regular_interrupt(0,dev,NULL);
}
int snull_tx(struct sk_buff *skb,struct net_device *dev)
{
	int len;
	char *data,shortpkt[ETH_ZLEN];
	struct snull_priv *priv = netdev_priv(dev);
	data = skb->data;
	len = skb->len;
	if(len < ETH_ZLEN){
		memset(shortpkt,0,ETH_ZLEN);
		memset(shortpkt,skb->data,skb->len);//传输大小为len的数据，后几位则为0
		len = ETH_ZLEN;
		data = shortpkt;	
	}
	dev->trans_start = jiffies;
	priv->skb = skb;
	snull_hw_tx(data,len,dev);
	return 0;
}
struct net_device_stats *snull_stats(struct net_device *dev)
{
	struct snull_priv *priv = netdev_priv(dev);
	return &priv->stats;
}

int snull_rebuild_header(struct sk_buff *skb)
{
	struct ethhdr *eth = (struct ethhdr *) skb->data;
	struct net_device *dev = skb->dev;
    
	memcpy(eth->h_source, dev->dev_addr, dev->addr_len);
	memcpy(eth->h_dest, dev->dev_addr, dev->addr_len);
	eth->h_dest[ETH_ALEN-1]   ^= 0x01;   /* dest is us xor 1 */
	return 0;
}


int snull_header(struct sk_buff *skb, struct net_device *dev,
                unsigned short type, const void *daddr, const void *saddr,
                unsigned len)
{
	struct ethhdr *eth = (struct ethhdr *)skb_push(skb,ETH_HLEN);

	eth->h_proto = htons(type);
	memcpy(eth->h_source, saddr ? saddr : dev->dev_addr, dev->addr_len);
	memcpy(eth->h_dest,   daddr ? daddr : dev->dev_addr, dev->addr_len);
	eth->h_dest[ETH_ALEN-1]   ^= 0x01;   /* dest is us xor 1 */
	return (dev->hard_header_len);
}


static const struct net_device_ops snull_netdev_ops = {//
	.ndo_open		= snull_open,//打开设备
	.ndo_stop		= snull_release,//关闭设备
	.ndo_set_config		= snull_config,//配置
	.ndo_start_xmit		= snull_tx,//传送包函数
	.ndo_get_stats		= snull_stats,
	.ndo_tx_timeout         = snull_tx_timeout,
};

static const struct header_ops snull_header_ops = {
	.create 	= snull_header,//创建
	.rebuild 	= snull_rebuild_header,//重建
	.cache 		= NULL,		//此处不需要更改
};

void snull_init(struct net_device *dev)
{
	struct snull_priv *priv;

	priv = netdev_priv(dev);
	memset(priv, 0, sizeof(struct snull_priv));
	spin_lock_init(&priv->lock);
	priv->dev = dev;
	ether_setup(dev); /* assign some of the fields */
	dev->watchdog_timeo = timeout;
	/* keep the default flags, just add NOARP */
	dev->flags           |= IFF_NOARP;
	dev->features        |= NETIF_F_HW_CSUM;
	dev->netdev_ops = &snull_netdev_ops;
	dev->header_ops = &snull_header_ops;

	snull_rx_ints(dev, 1);		/* enable receive interrupts */
	snull_setup_tx_queue(dev);
}



void snull_cleanup(void)//模块卸载
{
	int i;
    
	for (i = 0; i < 2;  i++) {
		if (snull_devs[i]) {
			unregister_netdev(snull_devs[i]);
			snull_teardown_tx_queue(snull_devs[i]);
			free_netdev(snull_devs[i]);
		}
	}
	return;
}

int snull_init_module(void)//模块初始化
{
	int result, i, ret = -ENOMEM;
	/* Allocate the devices */
	snull_devs[0] = alloc_netdev(sizeof(struct snull_priv), "sn%d",snull_init);
	snull_devs[1] = alloc_netdev(sizeof(struct snull_priv), "sn%d",snull_init);
	if (snull_devs[0] == NULL || snull_devs[1] == NULL)
		goto out;

	ret = -ENODEV;
	for (i = 0; i < 2;  i++)
		if ((result = register_netdev(snull_devs[i])))
			printk("snull: error %i registering device \"%s\"\n",
					result, snull_devs[i]->name);
		else
			ret = 0;
   out:
	if (ret) 
		snull_cleanup();
	return ret;
}

module_init(snull_init_module);
module_exit(snull_cleanup);

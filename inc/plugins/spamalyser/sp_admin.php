<?php

defined('IN_MYBB') or die('This file cannot be accessed directly.');

$plugins->add_hook('admin_config_settings_change', 'spamalyser_acp_settings');
$plugins->add_hook('admin_tools_menu_logs', 'spamalyser_acp_menu');
$plugins->add_hook('admin_tools_permissions', 'spamalyser_acp_perms');
$plugins->add_hook('admin_tools_action_handler', 'spamalyser_acp_action');

function spamalyser_info() {
	return array(
		'name'          => 'Spamalyser',
		'description'   => 'Tries to analyse posts from new users to detect some spam.',
		'website'       => 'http://mybbhacks.zingaburga.com/',
		'author'        => 'ZiNgA BuRgA',
		'authorsite'    => 'http://zingaburga.com/',
		'version'       => '0.93',
		'compatibility' => '14*,15*,16*,18*',
		'guid'          => ''
	);
}

function spamalyser_install() {
	global $db, $lang, $mybb;
	
	// grab current host
	// TODO: maybe use cookie domain as a hint too?
	$current_host = '';
	if(preg_match('~^https?\://([a-z0-9\-.]+)~i', $mybb->settings['bburl'], $m))
		$current_host = $m[1];
	
	// disable external lookups for localhost (testing) installations
	$is_localhost = (strtolower($current_host) == 'localhost' || $current_host == '127.0.0.1' || substr($current_host, 0, 8) == '192.168.');
	
	// grab valid language codes
	$langdir = @glob($lang->path.'/*.php');
	$langcodes = '';
	if(!empty($langdir)) foreach($langdir as &$langfile) {
		@include $langfile;
		if(is_array($langinfo) && $langinfo['htmllang']) {
			$langcodes .= ($langcodes?',':'') . $langinfo['htmllang'];
		}
		unset($langinfo);
	}
	if($langcodes === '') $langcodes = 'en';
	
	$lang->load('spamalyser');
	$gid = $db->insert_query('settinggroups', array(
		'name' => 'spamalyser',
		'title' => $db->escape_string($lang->setting_group_spamalyser),
		'description' => $db->escape_string($lang->setting_group_spamalyser_desc),
		'disporder' => 100,
		'isdefault' => 0,
	));
	$disporder = 0;
	foreach(array(
		'thresh_postcount' => array('text', 8, 0),
		'thresh_onlinetime' => array('text', 12*60, 0), // 12 hours
		'thresh_regtime' => array('text', 90*24, 0), // 3 months
		'thresh_pms' => array('text', 6, 0),
		'groups' => array('text', '1,2,5', 0), // guests, registered users and awaiting activation
		'safe_hosts' => array('textarea', 
			$current_host.($current_host ? "\r\n":'')
			.'google.{COM},googleusercontent.com,yahoo.{COM},bing.com,ask.com'."\r\n"
			.'facebook.com,twitter.com,linkedin.com,youtube.com,netflix.com,dailymotion.com,wikipedia.org'."\r\n"
			.'amazon.{COM},ebay.{COM},craigslist.org,paypal.{COM}'."\r\n"
			.'imdb.com,sourceforge.com,github.com,gitorious.com'."\r\n"
			.'baidu.com,qq.com,taobao.com,sina.com.cn,yandex.ru,163.com'."\r\n"
			.'bbc.co.uk,cnn.com,cnet.com,nytimes.com'."\r\n"
			.'mediafire.com,sendspace.com,zshare.com,megaupload.com,rapidshare.com,hotfile.com,fileserve.com,filesonic.com,wupload.com'."\r\n"
			.'bayimg.com,deviantart.com,flickr.com,freeimagehosting.net,imagehosting.com,imageshack.us,imgur.com,photobucket.com,tinypic.com,twitpic.com,webshots.com'."\r\n"
			// fotki.com,fotolog.com,fotopic.net,gazopa.com,imagevenue.com,imgplace.com,ipernity.com,jalbum.net,kodakgallery.{COM},lafango.com,phanfare.com,panoramio.com,piczo.com,selfportrait.net,shutterfly.com,smugmug.com,snapfish.*,twango.com,woophy.com,zooomr.com
			.'gov,edu,gov.*,edu.*,mil,int'."\r\n"
			.'microsoft.com,live.{COM},msn.{COM},adobe.com,apple.com', 0),
		//'thresh_links' => array('text', 0),
		'weight_link' => array('text', 0.15, 1),
		'link_limit' => array('text', 1, 1),
		'weight_complexlink' => array('text', 0.45, 1),
		'complexlink_limit' => array('text', 4, 1),
		'weight_samehost' => array('text', 0.15, 1),
		'weight_keyword' => array('text', 0.17, 1),
		'weight_badword' => array('text', 1.4, 1),
		'ignore_quotelinks' => array('select|safe|any|off', 'safe', 1),
		'posthist_time' => array('text', '720', 1),
		'weight_editdiff' => array('text', 0.5, 1),
		'editdiff_grace' => array('text', 5, 1),
		'weight_oldbump' => array('text', 0.007, 1),
		'mweight_oldbump' => array('text', 0.3, 1),
		'dforums' => array('text', '', 1),
		'weight_dforums' => array('text', 1.5, 1),
		
		'weight_sig' => array('text', 1.8, 2),
		'weight_onlinetime' => array('text', 0.25, 2),
		'weight_postcount' => array('text', 0, 2), // previously 0.05; now somewhat redundant with the posttimes setting
		'weight_regtime' => array('text', 0, 2),
		'weight_posttimes' => array('text', 0.01, 2),
		'posttimes_maxtime' => array('text', 60, 2),
		'weight_ipdiff' => array('text', 0.01, 2),
		'weight_markreport' => array('text', 0.35, 2),
		
		'weight_sfs_username' => array('text', $is_localhost?0: 0.05, 3),
		'weight_sfs_email' => array('text', $is_localhost?0: 0.8, 3),
		'weight_sfs_ip' => array('text', $is_localhost?0: 0.6, 3),
		'sfs_limit' => array('text', 13, 3),
		
		'aki_key' => array('text', '', 4),
		'weight_aki_spam' => array('text', 6, 4),
		'weight_aki_ham' => array('text', 0, 4),
		'aki_trigger_edit' => array('yesno', 0, 4),
		
		'weight_glang' => array('text', $is_localhost?0: 2, 5),
		'glang_safe' => array('text', $langcodes, 5),
		'weight_gsearch' => array('text', $is_localhost?0: 0.2, 5),
		'mweight_gsearch' => array('text', 3, 5),
		'gsearch_minlen' => array('text', 50, 5),
		
		'tweight_report' => array('text', 1, 8),
		'tweight_unapprove' => array('text', 10, 8),
		'tweight_block' => array('text', 15, 8),
		'no_block_edit' => array('yesno', 1, 8),
		'keyword_minlen' => array('text', 4, 9),
		'keyword_safe' => array('text', 'html,htm,phtml,php,php3,php4,php5,cgi,pl,asp,aspx,jsp,jpg,jpeg,png,gif,zip,rar,7z,tar,gz,bz2,xz,download,click,link,source,src,i,grab,email,website,showthread,viewthread,forumdisplay,showforum,viewtopic,showtopic,newthread,newreply,usercp,'.
		// the following list is taken from the MySQL stopwords list: http://dev.mysql.com/doc/refman/5.5/en/fulltext-stopwords.html
		'a\'s,able,about,above,according,accordingly,across,actually,after,afterwards,again,against,ain\'t,all,allow,allows,almost,alone,along,already,also,although,always,am,among,amongst,an,and,another,any,anybody,anyhow,anyone,anything,anyway,anyways,anywhere,apart,appear,appreciate,appropriate,are,aren\'t,around,as,aside,ask,asking,associated,at,available,away,awfully,be,became,because,become,becomes,becoming,been,before,beforehand,behind,being,believe,below,beside,besides,best,better,between,beyond,both,brief,but,by,c\'mon,c\'s,came,can,can\'t,cannot,cant,cause,causes,certain,certainly,changes,clearly,co,com,come,comes,concerning,consequently,consider,considering,contain,containing,contains,corresponding,could,couldn\'t,course,currently,definitely,described,despite,did,didn\'t,different,do,does,doesn\'t,doing,don\'t,done,down,downwards,during,each,edu,eg,eight,either,else,elsewhere,enough,entirely,especially,et,etc,even,ever,every,everybody,everyone,everything,everywhere,ex,exactly,example,except,far,few,fifth,first,five,followed,following,follows,for,former,formerly,forth,four,from,further,furthermore,get,gets,getting,given,gives,go,goes,going,gone,got,gotten,greetings,had,hadn\'t,happens,hardly,has,hasn\'t,have,haven\'t,having,he,he\'s,hello,help,hence,her,here,here\'s,hereafter,hereby,herein,hereupon,hers,herself,hi,him,himself,his,hither,hopefully,how,howbeit,however,i\'d,i\'ll,i\'m,i\'ve,ie,if,ignored,immediate,in,inasmuch,inc,indeed,indicate,indicated,indicates,inner,insofar,instead,into,inward,is,isn\'t,it,it\'d,it\'ll,it\'s,its,itself,just,keep,keeps,kept,know,known,knows,last,lately,later,latter,latterly,least,less,lest,let,let\'s,like,liked,likely,little,look,looking,looks,ltd,mainly,many,may,maybe,me,mean,meanwhile,merely,might,more,moreover,most,mostly,much,must,my,myself,name,namely,nd,near,nearly,necessary,need,needs,neither,never,nevertheless,new,next,nine,no,nobody,non,none,noone,nor,normally,not,nothing,novel,now,nowhere,obviously,of,off,often,oh,ok,okay,old,on,once,one,ones,only,onto,or,other,others,otherwise,ought,our,ours,ourselves,out,outside,over,overall,own,particular,particularly,per,perhaps,placed,please,plus,possible,presumably,probably,provides,que,quite,qv,rather,rd,re,really,reasonably,regarding,regardless,regards,relatively,respectively,right,said,same,saw,say,saying,says,second,secondly,see,seeing,seem,seemed,seeming,seems,seen,self,selves,sensible,sent,serious,seriously,seven,several,shall,she,should,shouldn\'t,since,six,so,some,somebody,somehow,someone,something,sometime,sometimes,somewhat,somewhere,soon,sorry,specified,specify,specifying,still,sub,such,sup,sure,t\'s,take,taken,tell,tends,th,than,thank,thanks,thanx,that,that\'s,thats,the,their,theirs,them,themselves,then,thence,there,there\'s,thereafter,thereby,therefore,therein,theres,thereupon,these,they,they\'d,they\'ll,they\'re,they\'ve,think,third,this,thorough,thoroughly,those,though,three,through,throughout,thru,thus,to,together,too,took,toward,towards,tried,tries,truly,try,trying,twice,two,un,under,unfortunately,unless,unlikely,until,unto,up,upon,us,use,used,useful,uses,using,usually,value,various,very,via,viz,vs,want,wants,was,wasn\'t,way,we,we\'d,we\'ll,we\'re,we\'ve,welcome,well,went,were,weren\'t,what,what\'s,whatever,when,whence,whenever,where,where\'s,whereafter,whereas,whereby,wherein,whereupon,wherever,whether,which,while,whither,who,who\'s,whoever,whole,whom,whose,why,will,willing,wish,with,within,without,won\'t,wonder,would,wouldn\'t,yes,yet,you,you\'d,you\'ll,you\'re,you\'ve,your,yours,yourself,yourselves,zero'
		, 9),
		'keyword_bad' => array('text', 'seo,rich,money,cash,gold,forex,cheap,cheapest,sale,purchase,wholesale,price,prices,estate,poker,blackjack,holdem,casino,gambling,dumps,logins,clothing,shoes,boots,porn,porno,amateur,cam,sex,sexy,viagra,vagina,vaginal,penis,cock,horny,cialis,cigarettes,smoking,marijuana,prescription,capsules,pharmacies,pharmacy,pharmaceutical,drug,drugs,pill,pills,drugstore,weight,weightloss,replica', 9),
		
		'report_uid' => array('text', $mybb->user['uid'], 9), // or "1"
		'report_nodupe' => array('yesno', 1, 9),
		
		// reporting, link removal, unapprove, delete, ban weightings
	) as $name => $opts) {
		$lang_title = 'setting_spamalyser_'.$name;
		$lang_desc = 'setting_spamalyser_'.$name.'_desc';
		$order = ++ $disporder;
		if($opts[2]) $order += $opts[2]*100;
		if(strpos($opts[0], '|')) {
			$sopt = explode('|', $opts[0]);
			for($i=1, $c=count($sopt); $i<$c; ++$i) {
				$lang_opt = $lang_title.'_'.$sopt[$i];
				$sopt[$i] = $sopt[$i].'='.$lang->$lang_opt;
			}
			$opts[0] = $db->escape_string(implode("\n", $sopt));
		}
		$db->insert_query('settings', array(
			'name'        => 'spamalyser_'.$name,
			'title'       => $db->escape_string($lang->$lang_title),
			'description' => $db->escape_string($lang->$lang_desc),
			'optionscode' => $opts[0],
			'value'       => $db->escape_string($opts[1]),
			'disporder'   => $order,
			'gid'         => $gid,
		));
	}
	rebuild_settings();
	
	$is_mysql = ($db->type == 'mysql' || $db->type == 'mysqli');
	$collation = ($is_mysql ? ' ENGINE=MyISAM'.$db->build_create_table_collation():'');
	// TODO: proper support for non-MySQL DBMS
	$db->write_query('CREATE TABLE '.$db->table_prefix.'spamalyser_sfs_cache (
		data varchar(200) not null,
		type tinyint(3) not null, -- 1=username, 2=email, 3=ip
		lastcheck bigint(30) not null default 0,
		frequency int(10) unsigned not null default 0,
		'.($is_mysql ? 'PRIMARY KEY (data,type)':'').'
	)'.$collation);
	$db->write_query('CREATE TABLE '.$db->table_prefix.'spamalyser_log (
		lid int(11) unsigned not null auto_increment,
		pid int(11) unsigned not null default 0,
		event tinyint(3) not null, -- 0=newpost, 1=editpost, 2=newpost (automerged)
		
		-- the following may be considered redundant, but is required if posts get deleted/blocked etc
		threadsubject varchar(100) not null default "", -- blank if new thread
		subject varchar(100) not null default "",
		message text not null,
		tid int(11) unsigned not null default 0,
		fid int(11) unsigned not null default 0,
		uid int(11) unsigned not null default 0,
		username varchar(70) not null default "",
		ipaddress varchar(50) not null default "",
		httpreq text not null,
		timeonline int(11) unsigned not null default 0,
		postcount int(11) unsigned not null default 0,
		-- store signature? email?
		
		score float not null default 0,
		details text not null,
		actions varchar(50) not null default "",
		dateline bigint(30) not null default 0,
		'.($is_mysql ? 'PRIMARY KEY (lid), KEY (dateline)':'').'
	)'.$collation);
	
	
	// admin permissions - default to all allow
	$query = $db->simple_select('adminoptions', 'uid,permissions');
	while($adminopt = $db->fetch_array($query)) {
		$perms = unserialize($adminopt['permissions']);
		$perms['tools']['spamalyserlog'] = 1;
		$db->update_query('adminoptions', array('permissions' => $db->escape_string(serialize($perms))), 'uid='.$adminopt['uid']);
	}
	$db->free_result($query);
}
function spamalyser_activate() {
	global $db, $lang;
	if(!$lang->spamalyser_prunelogtask_name) $lang->load('spamalyser');
	$db->insert_query('tasks', array(
		'title' => $db->escape_string($lang->spamalyser_prunelogtask_name),
		'description' => $db->escape_string($lang->spamalyser_prunelogtask_desc),
		'file' => 'spamalyser_prunelog',
		'minute' => '20',
		'hour' => '12',
		'day' => '7',
		'month' => '*',
		'weekday' => '*',
		'nextrun' => TIME_NOW + 86400*200,
		'lastrun' => 0,
		'enabled' => 1,
		'logging' => 1,
		'locked' => 0,
	));
	$GLOBALS['cache']->update_tasks();
}

function spamalyser_is_installed() {
	global $db;
	//return $db->fetch_field($db->simple_select('settinggroups', 'gid', "name='spamalyser'"), 'gid');
	return $db->table_exists('spamalyser_sfs_cache');
}

function spamalyser_deactivate() {
	$GLOBALS['db']->delete_query('tasks', 'file="spamalyser_prunelog"');
	$GLOBALS['cache']->update_tasks();
}
function spamalyser_uninstall() {
	global $db;
	$gid = $db->fetch_field($db->simple_select('settinggroups', 'gid', "name='spamalyser'"), 'gid');
	if($gid) {
		$db->delete_query('settings', 'gid='.$gid);
		$db->delete_query('settinggroups', 'gid='.$gid);
		rebuild_settings();
	}
	$db->drop_table('spamalyser_sfs_cache');
	$db->drop_table('spamalyser_log');
	
	$query = $db->simple_select('adminoptions', 'uid,permissions');
	while($adminopt = $db->fetch_array($query)) {
		$perms = unserialize($adminopt['permissions']);
		unset($perms['tools']['spamalyserlog']);
		$db->update_query('adminoptions', array('permissions' => $db->escape_string(serialize($perms))), 'uid='.$adminopt['uid']);
	}
	$db->free_result($query);
}

function spamalyser_acp_settings() {
	global $mybb, $db;
	if($mybb->request_method == 'post' || $mybb->input['search'] || !$mybb->input['gid']) return;
	// just run an extra query rather than trying to do something tricky
	$groupname = $db->fetch_field($db->simple_select('settinggroups', 'name', 'gid='.(int)($mybb->input['gid'])), 'name');
	if($groupname != 'spamalyser') return;
	
	global $plugins, $lang;
	$plugins->add_hook('admin_formcontainer_output_row', 'spamalyser_acp_settings_row');
	// special case for first table - we need to delay setting the title
	$plugins->add_hook('admin_page_output_header', 'spamalyser_acp_settings_firsttitle');
	$lang->load('spamalyser');
}
function spamalyser_acp_settings_firsttitle() {
	global $lang;
	$lang->setting_group_spamalyser = $lang->spamalyser_settingsgrp_0;
}
function spamalyser_acp_settings_row(&$a) {
	global $setting;
	static $prev_grp = 0;
	$grp = (int)($setting['disporder'] / 100);
	if($prev_grp != $grp) {
		$prev_grp = $grp;
		global $form_container, $lang;
		$form_container->end();
		$langstr = 'spamalyser_settingsgrp_'.$grp;
		$form_container->_title = $lang->$langstr;
	}
}

function spamalyser_acp_menu(&$sm) {
	global $lang;
	if(!$lang->spamalyser_logs) $lang->load('spamalyser');
	$sep = ($GLOBALS['mybb']->version_code >= 1500 ? '-':'/');
	$sm['53'] = array('id' => 'spamalyserlog', 'title' => $lang->spamalyser_logs, 'link' => 'index.php?module=tools'.$sep.'spamalyserlog');
	ksort($sm); // one would presume that this should be done by MyBB...
}
function spamalyser_acp_perms(&$perms) {
	global $lang;
	if(!$lang->can_view_spamalyserlog) $lang->load('spamalyser');
	$perms['spamalyserlog'] = $lang->can_view_spamalyserlog;
}
function spamalyser_acp_action(&$actions) {
	$actions['spamalyserlog'] = array('active' => 'spamalyserlog', 'file' => 'spamalyserlog.php');
}

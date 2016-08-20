<?php

defined('IN_MYBB') or die('This file cannot be accessed directly.');

define('SPAMALYSER_SFS_CACHE_EXPIRY', 6*3600); // expire SFS cache after 6 hours

function spamalyser_run(&$ph, $newthread, $newpost, $fid, $postcount) {
	$settings =& $GLOBALS['mybb']->settings;
	$user =& $GLOBALS['mybb']->user;
	$data =& $ph->data;
	$pid = (int)$data['pid'];
	$tid = (int)$data['tid'];
	if(!$newpost && $pid) {
		$post = get_post($pid); // cached fetch
	}
	
	$ip = $data['ipaddress'];
	if(!$ip) $ip = get_ip();
	
	global $db;
	$components = array(); // record the components for logging
	
	
	if($user['uid']) {
		$onlinetime = max($user['timeonline']/60, 0);
		$regtime = max((TIME_NOW - $user['regdate'])/3600, 0);
	} else {
		$onlinetime = $regtime = 0;
	}
	
	$postcount_weight = (float)$settings['spamalyser_weight_postcount'];
	$onlinetime_weight = (float)$settings['spamalyser_weight_onlinetime'];
	$regtime_weight = (float)$settings['spamalyser_weight_regtime'];
	$ipdiff_weight = (float)$settings['spamalyser_weight_ipdiff'];
	$oldbump_weight = (float)$settings['spamalyser_weight_oldbump'];
	$weight_reduction = $postcount * $postcount_weight
	                  - ($onlinetime > 0 ? $onlinetime_weight/$onlinetime : 0)
	                  + $regtime * $regtime_weight;
	
	if($postcount_weight) $components['postcount'] = -$postcount * $postcount_weight;
	if($onlinetime_weight && $onlinetime) $components['onlinetime'] = $onlinetime_weight/$onlinetime;
	if($regtime_weight) $components['regtime'] = -$regtime * $regtime_weight;
	
	if($ipdiff_weight && $user['regip'] && preg_match('~^(\d{1,3}\.){3}\d{1,3}$~', $ip)) {
		// calculate difference by XORing binary forms of IP addresses, and finding the highest bit
		$ipmask = ip2long($ip) ^ ip2long($user['regip']);
		$ipdiff = 0;
		while($ipmask) {
			$ipmask >>= 1;
			++$ipdiff;
			if($ipdiff > 31) break; // PHP doesn't like shifting more than 31 bits
		}
		$components['ipdiff'] = $ipdiff_weight * $ipdiff;
		$weight_reduction -= $components['ipdiff'];
	}
	if($newpost && $oldbump_weight && $tid) {
		$thread = get_thread($tid);
		if($thread['visible'] == 1) { // ensure this thread isn't a draft
			$components['oldbump'] = max((TIME_NOW - $thread['lastpost'])/86400, 0) * $oldbump_weight;
			$max_oldbump = (float)$settings['spamalyser_mweight_oldbump'];
			if($max_oldbump) $components['oldbump'] = min($components['oldbump'], $max_oldbump);
			$weight_reduction -= $components['oldbump'];
		}
	}
	
	$forumweight = 1;
	if($settings['spamalyser_dforums'] && $settings['spamalyser_weight_dforums'] != '1') {
		$dforums = array_map('intval', array_map('trim', explode(',', $settings['spamalyser_dforums'])));
		if($fid && in_array($fid, $dforums))
			$forumweight = (float)$settings['spamalyser_weight_dforums'];
	}
	if($forumweight <= 0) return;
	
	
	// check whether link analysis is enabled
	$do_link_analysis = (
		(float)$settings['spamalyser_weight_link'] ||
		(float)$settings['spamalyser_weight_complexlink'] ||
		(float)$settings['spamalyser_weight_keyword']
	);
	$weight_posttimes = (float)$settings['spamalyser_weight_posttimes'];
	$posttimes_maxtime = (float)$settings['spamalyser_posttimes_maxtime'] * 3600;
	
	if($do_link_analysis) {
		$ignore_links = spamalyser_grab_quote_links($data['message'], $pid);
		
		$common_domains = $common_keywords = array();
		// gather keywords/hosts from previous posts
		if($user['uid'] && trim($settings['spamalyser_posthist_time']) !== '') { // TODO: perhaps check by IP address for guests
			$posthist_time = (int)$settings['spamalyser_posthist_time'];
			$qx = '';
			if($posthist_time) {
				$posthist_time = TIME_NOW - $posthist_time*60;
				$qx .= ' AND (dateline >= '.$posthist_time.' OR edittime >= '.$posthist_time.')';
			} elseif($weight_posttimes)
				$user_pposttime = 0;
			if($pid) $qx .= ' AND pid!='.$pid;
			
			//$query = $db->simple_select('posts', 'message', 'uid='.$user['uid'].$qx);
			$query = $db->simple_select('posts', 'message'.(isset($user_pposttime) ? ',dateline,edittime,visible,edituid':''), 'uid='.$user['uid'].' AND visible IN (0,1)'.$qx);
			while($prevmsg = $db->fetch_array($query)) {
				spamalyser_accum_dom_kw($prevmsg['message'], $common_domains, $common_keywords, $ignore_links);
				// cache this info for later use (if we use it)
				if($prevmsg['visible'] == 1 && (!$prevmsg['edituid'] || $prevmsg['edituid'] == $user['uid'])) {
					$add_pptime = max(TIME_NOW - max($prevmsg['edittime'], $prevmsg['dateline']), 0);
					if($posttimes_maxtime) $add_pptime = min($add_pptime, $posttimes_maxtime);
					$user_pposttime += $add_pptime;
				}
			}
			$db->free_result($query);
		}
	}
	
	// weight reduction based on user's previous post times
	if($newpost && $user['uid']) { // only consider this for new posts, since we can't tell whether edits are innocent or a spammer coming back to add links
		if($weight_posttimes = (float)$settings['spamalyser_weight_posttimes']) {
			if(!isset($user_pposttime)) {
				// not cached: grab posttime info
				$user_pposttime = 0;
				$query = $db->simple_select('posts', 'dateline,edittime', 'uid='.$user['uid'].' AND visible=1 AND edituid IN (0,'.$user['uid'].')');
				while($t = $db->fetch_array($query)) {
					$add_pptime = max(TIME_NOW - max($t['edittime'], $t['dateline']), 0);
					if($posttimes_maxtime) $add_pptime = min($add_pptime, $posttimes_maxtime);
					$user_pposttime += $add_pptime;
				}
				$db->free_result($query);
			}
			if($user_pposttime) {
				// calculate stuff
				$components['posttimes'] = ($user_pposttime)/3600 * -$weight_posttimes;
				$weight_reduction -= $components['posttimes'];
			}
		}
	}
	
	if($do_link_analysis) {
		// look at user's signature - problem with this is that it won't have keywords/domains from main post; will consider previous posts though
		if($settings['spamalyser_weight_sig'] && $user['signature']) {
			$components['sig'] = spamalyser_calc_msg_weight($user['signature'], $common_domains, $common_keywords, $ignore_links) * (float)$settings['spamalyser_weight_sig'];
			$weight_reduction -= $components['sig'];
		}
		
		// make backup copy of the gathered domains/keywords for editing checks
		$base_domains = $common_domains;
		$base_keywords = $common_keywords;
		$components['msg'] = $postweight = spamalyser_calc_msg_weight($data['message'], $common_domains, $common_keywords, $ignore_links);
		
		if(!$newpost && $pid && $settings['spamalyser_weight_editdiff']) {
			// calculate weighting of existing post
			$editgrace = (float)$settings['spamalyser_editdiff_grace'];
			if((TIME_NOW - $post['dateline'])/60 >= $editgrace) {
				$oldpostweight = spamalyser_calc_msg_weight($post['message'], $base_domains, $base_keywords, $ignore_links);
				$components['editbonus'] = max($postweight - $oldpostweight, 0) * (float)$settings['spamalyser_weight_editdiff'];
				$postweight += $components['editbonus'];
			}
		}
	}
	
	// SFS check
	// for guests, we only perform an IP check
	if($user['uid'] || $ip) {
		// TODO: be smarter about queries (eg, don't force search for something if weight=0)
		if($user['uid']) {
			$sfsw_username = (float)$settings['spamalyser_weight_sfs_username'];
			$sfsw_email = (float)$settings['spamalyser_weight_sfs_email'];
		} else // guests don't have username/email weighting
			$sfsw_username = $sfsw_email = 0;
		$sfsw_ip = (float)$settings['spamalyser_weight_sfs_ip'];
		$sfsw_limit = (float)$settings['spamalyser_sfs_limit'];
		if($sfsw_username || $sfsw_email || $sfsw_ip) {
			// check if we have this cached
			// note that we'll store everything regardless of what's enabled - this means we'll have a good cache if the setting happens to be changed later
			// use current IP instead of registration IP
			// we'll prevent some cases with blank IPs
			
			$qx = ''; $expected_rows = 0;
			if($user['uid']) {
				$qx = '(data="'.$db->escape_string($user['username']).'" AND type=1) OR
				(data="'.$db->escape_string($user['email']).'" AND type=2)';
				$expected_rows += 2;
			}
			if($ip) {
				$qx .= ($qx ? ' OR ':'').'(data="'.$db->escape_string($ip).'" AND type=3)';
				++$expected_rows;
			}
			// internally expire cache after 1 day
			$query = $db->simple_select('spamalyser_sfs_cache', 'type,frequency', 'lastcheck > '.(TIME_NOW-SPAMALYSER_SFS_CACHE_EXPIRY).' AND ('.$qx.')');
			if($db->num_rows($query) == $expected_rows) {
				// cache hit!
				while($sfsq = $db->fetch_array($query)) {
					$sfs[(int)$sfsq['type']] = $sfsq['frequency'];
				}
				// default to 0 if not grabbed
				isset($sfs[1]) or $sfs[1] = 0;
				isset($sfs[2]) or $sfs[2] = 0;
				isset($sfs[3]) or $sfs[3] = 0;
			} else {
				// we have to query SFS for everything
				$sfs_qry = '';
				if($user['uid'])
					$sfs_qry = 'username='.rawurlencode($user['username']).'&email='.rawurlencode($user['email']);
				if($ip) $sfs_qry .= ($sfs_qry?'&':'') . 'ip='.rawurlencode($ip);
				$sfs_data = fetch_remote_file('http://www.stopforumspam.com/api?'.$sfs_qry.'&f=serial');
				if($sfs_data) {
					$sfs_data = @unserialize($sfs_data);
					if(!empty($sfs_data) && $sfs_data['success']) {
						// randomly prune cache before updating
						if(!mt_rand(0,9))
							$db->delete_query('spamalyser_sfs_cache', 'lastcheck <= '.(TIME_NOW - SPAMALYSER_SFS_CACHE_EXPIRY));
						
						$sfs = array(
							// for Guests, username/email won't be returned, so conveniently will be set to 0 for us
							1 => (int)$sfs_data['username']['frequency'],
							2 => (int)$sfs_data['email']['frequency'],
							3 => (int)$sfs_data['ip']['frequency'], // will be 0 if not queried
						);
						// update cache
						foreach(array(1=>$user['username'], 2=>$user['email'], 3=>$ip) as $type => $sfs_data) {
							if((!$user['uid'] && $type != 3) || ($type == 3 && !$sfs_data)) continue;
							$db->replace_query('spamalyser_sfs_cache', array(
								'type' => $type,
								'data' => $db->escape_string($sfs_data),
								'lastcheck' => TIME_NOW,
								'frequency' => $sfs[$type]
							));
						}
					}
				}
			}
			$db->free_result($query);
			$sfs_weight = $sfsw_username * $sfs[1] + $sfsw_email * $sfs[2] + $sfsw_ip * $sfs[3];
			if($sfsw_limit && $sfs_weight > $sfsw_limit) $sfs_weight = $sfsw_limit;
			$weight_reduction -= $sfs_weight;
			$components['sfs'] = $sfs_weight;
		}
	}
	
	// Akismet check
	$aki_spam_weight = (float)$settings['spamalyser_weight_aki_spam'];
	$aki_ham_weight = (float)$settings['spamalyser_weight_aki_ham'];
	if(preg_match('~^[a-f0-9]{12}$~', $settings['spamalyser_aki_key']) && ($aki_spam_weight || $aki_ham_weight) && ($settings['spamalyser_aki_trigger_edit'] || $newpost) && (function_exists('curl_init') || function_exists('fsockopen'))) {
		$aki_args = array(
			'blog' => $settings['bburl'],
			'user_ip' => $ip,
			'user_agent' => $_SERVER['HTTP_USER_AGENT'],
			'referrer' => $_SERVER['HTTP_REFERER'],
			'comment_type' => 'post', // as per default in MyBB's Akismet plugin; PunBB mod uses 'punbb', phpBB's uses 'forum_post', Phorum uses 'forum', SMF uses 'smf-post'
			'comment_content' => $data['message'] // sent unparsed because that's what the MyBB Akismet plugin (as well as all the other forum Akismet plugins, it seems) does - don't know whether this is appropriate though
		);
		if($user['uid']) {
			$aki_args['comment_author'] = $user['username'];
			$aki_args['comment_author_email'] = $user['email'];
			if($user['website'])
				$aki_args['comment_author_url'] = $user['website']; // should we include the website though?
		} elseif($data['username'])
			$aki_args['comment_author'] = $data['username'];
		
		if($newthread)
			$aki_args['permalink'] = $settings['bburl'].'/forumdisplay.php?fid='.$fid;
		else {
			$thread_id = $tid;
			if(!$thread_id && !empty($post)) $thread_id = $post['tid'];
			if($thread_id) {
				$aki_args['permalink'] = $settings['bburl'].'/showthread.php?tid='.$thread_id;
			}
		}
		
		$aki_data = strtolower(fetch_remote_file('http://'.$settings['spamalyser_aki_key'].'.rest.akismet.com/1.1/comment-check', $aki_args));
		
		if($aki_data == 'true')
			$components['akismet'] = $aki_spam_weight;
		elseif($aki_data == 'false')
			$components['akismet'] = -$aki_ham_weight;
		if(isset($components['akismet']))
			$weight_reduction -= $components['akismet'];
	}
	
	// Google lang check
	if(($glang_weight = (float)$settings['spamalyser_weight_glang']) && $settings['spamalyser_glang_safe']) {
		// generate stripped message to query through Google
		// strip auto-urls and simple urls because they may mess up language detection
		$msg = preg_replace(array(
			'~\[url\][^\r\n"<]+?\[/url\]~is',
			'~(?<=[^a-z0-9])(https?\://[^\/"\s\<\[\.]+|www|ftp)\.([^\/"\s\<\[\.]+\.)*[\w]+(\:[0-9]+)?(/[^"\s<\[]*)?~i'
		), ' ', $data['message']);
		if($msg == $data['message']) // nothing stripped -> we can cache the result for later
			$msg = $msg_parsed = spamalyser_parse_msg($data['message']);
		else
			$msg = spamalyser_parse_msg($msg);
		// hard limit query to 1024 chars
		//$msg = strtr($msg, array("\r" => ' ', "\n" => ' '));
		//$p = spamalyser_strrpos($msg, ' ', 1024);
		//$msg = my_substr($msg, 0, $p);
		$msg = spamalyser_keyword_trim(strtr($msg, array("\r" => ' ', "\n" => ' ')), 1024);
		
		$gdata = fetch_remote_file('http://www.google.com/uds/GlangDetect?v=1.0&q='.urlencode($msg));
		unset($msg);
		if(function_exists('json_decode')) // only available PHP >= 5.2.0
			$gdata = json_decode($gdata, true);
		// this is somewhat less reliable (cos I'm too lazy to write a more proper parser)
		elseif(preg_match('~\{"language"\:"([a-zA-Z]+)","isReliable"\:(true|false),"confidence"\:([0-9.]+)\}~i', $gdata, $gm)) {
			$gdata = array('responseData' => array(
				'language' => $gm[1],
				'isReliable' => (bool)$gm[2],
				'confidence' => (float)$gm[3]
			));
		}
		else
			$gdata = false;
		if(!empty($gdata) && !empty($gdata['responseData'])) {
			$gdata = $gdata['responseData'];
			if($gdata['language'] && strpos(','.strtolower(str_replace(' ','',$settings['spamalyser_glang_safe'])).',', ','.strtolower($gdata['language']).',') === false) {
				$components['google_lang'] = $glang_weight * min((float)$gdata['confidence'], 1);
				$weight_reduction -= $components['google_lang'];
			}
		}
	}
	
	// Google search
	if($gsearch_weight = (float)$settings['spamalyser_weight_gsearch']) {
		if(!isset($msg_parsed)) // see if we can use cached copy
			$msg_parsed = spamalyser_parse_msg($data['message']);
		// we need to try to generate quoted queries which aren't too long, but also reasonably demonstrate the post content... :/
		$msg = explode("\n", str_replace("\r", "\n", $msg_parsed));
		$mcnt = 0;
		foreach($msg as $k => &$msgln) {
			if($mcnt > 5 || my_strlen($msgln) < 10) { // too short; TODO: but we already have a minimum length limit...
				unset($msg[$k]);
			} else {
				$msgln = spamalyser_keyword_trim($msgln, 128); // TODO: perhaps think about appending chopped off words to a new array element
				++$mcnt;
			}
		}
		if(!empty($msg)) {
			$msg = '"'.implode('" "', $msg).'"';
			$min_gsearch_len = (int)$settings['spamalyser_gsearch_minlen'];
			if(!$min_gsearch_len || my_strlen($msg) > $min_gsearch_len) {
				$results = spamalyser_num_google_results($msg);
				if($results !== false) {
					$google_weight = (float)$results * $gsearch_weight;
					if($max_google_weight = (float)$settings['spamalyser_mweight_gsearch'])
						$google_weight = min($google_weight, $max_google_weight);
					$components['google_search'] = $google_weight;
					$weight_reduction -= $google_weight;
				}
			}
		}
		unset($msg);
	}
	
	
	$postweight = $postweight * $forumweight - $weight_reduction;
	
	if($user['uid'] && ($markreport_weight = (float)$settings['spamalyser_weight_markreport'])) {
		$qx = '';
		if($pid) $qx = ' AND p.pid!='.$pid;
		
		$numreports = $db->fetch_field($db->query('
			SELECT COUNT(DISTINCT p.pid) AS numreports
			FROM '.TABLE_PREFIX.'posts p
			INNER JOIN '.TABLE_PREFIX.'reportedcontent r ON r.id=p.pid
			WHERE p.uid='.$user['uid'].' AND p.visible=1 AND r.reportstatus!=0 AND (r.type="post" OR type="")'.$qx
		), 'numreports');
		$report_weight = min($numreports * $markreport_weight, 1) * max($postweight, 0);
		$components['markedreports'] = -$report_weight;
		$postweight -= $report_weight;
	}
	
	$logentry = array(
		'event' => ($newpost ? 0:1), // 2 for merge -> set later
		'score' => $postweight,
		'details' => $db->escape_string(serialize($components)),
		'dateline' => TIME_NOW,
		
		'message' => $db->escape_string($data['message']),
		'uid' => (int)$user['uid'],
		'username' => $db->escape_string($user['username']),
		'fid' => $fid,
		'ipaddress' => $db->escape_string($ip),
		'httpreq' => $db->escape_string(spamalyser_get_http_headers()),
		'timeonline' => $onlinetime,
		'postcount' => $postcount,
		
		'actions' => ''
	);
	if(!$user['uid'] && $data['username'] !== '') // use supplied username for Guests
		$logentry['username'] = $db->escape_string($data['username']);
	if($tid) $logentry['tid'] = $tid;
	  elseif(!empty($post)) $logentry['tid'] = $post['tid'];
	if($pid) $logentry['pid'] = $pid;
	if(isset($data['subject'])) $logentry['subject'] = $db->escape_string($data['subject']);
	  elseif($pid) $logentry['subject'] = $db->escape_string($post['subject']);
	if($logentry['tid']) {
		$thread = get_thread($logentry['tid']);
		if(!$newthread && (!$pid || $thread['firstpost'] != $pid)) // only set threadsubject if not first post
			$logentry['threadsubject'] = $db->escape_string($thread['subject']);
	}
	if(!empty($ph->errors)) // UPDATE: this is now pointless
		$logentry['actions'] = 'errors'; // somewhat unreliable, but may work
	
	$thresh_report = (float)$settings['spamalyser_tweight_report'];
	$thresh_unapprove = (float)$settings['spamalyser_tweight_unapprove'];
	$thresh_block = (float)$settings['spamalyser_tweight_block'];
	if($thresh_block && $postweight > $thresh_block && ($newpost || !$settings['spamalyser_no_block_edit'])) {
		// simply block this post
		$GLOBALS['lang']->load('spamalyser');
		$ph->set_error('spam_blocked');
		
		$logentry['actions'] .= ($logentry['actions']?',':'') . 'blocked';
		$db->insert_query('spamalyser_log', $logentry);
	} elseif(empty($ph->errors)) { // not definite, but only try to run this if likely to go through; a slight issue is possible duplication of log entries in some cases
		
		// check for post merge
		if($newpost && !$newthread) {
			$double_post = $ph->verify_post_merge();
			$forum = get_forum($fid);
			if($double_post === true || $double_post['visible'] != 1 || !$double_post['pid'])
				unset($double_post);
			elseif($thresh_unapprove && $postweight > $thresh_unapprove)
				// if we're going to unapprove this post, post merging won't apply
				unset($double_post);
			// otherwise, try our best to check if the post will be moderated
			elseif($user['moderateposts'] || $forum['modposts'])
				unset($double_post);
			else {
				// well, looks like it'll go through
				$logentry['pid'] = $double_post['pid'];
				//$logentry['actions'] .= ($logentry['actions']?',':'') . 'automerge';
				$logentry['event'] = 2;
			}
		}
		
		if($thresh_report && $postweight > $thresh_report) {
			// report post
			if($pid)
				$reported = spamalyser_report_post($pid, $postweight);
			elseif(isset($double_post) && $double_post['pid'])
				$reported = spamalyser_report_post($double_post['pid'], $postweight);
			elseif($newpost) {
				// insert new post - need to defer action as we need the pid
				$data['spamalyser_postweight'] = $postweight;
				$data['spamalyser_actions'] = $logentry['actions'];
				$logentry['actions'] =& $data['spamalyser_actions']; // pass through future updates :P
				$reported = false;
			}
			if($reported)
				$logentry['actions'] .= ($logentry['actions']?',':'') . 'reported';
		}
		// only try to unapprove if the system isn't going to do it already
		if($thresh_unapprove && $postweight > $thresh_unapprove && !(
			// check if post is going to be unapproved already before trying to do so
			(!$newpost && $forum['mod_edit_posts']) ||
			($newpost && ($forum['modposts'] || ($forum['modthreads'] && $newthread) || $user['moderateposts']))
		)) {
			// unapprove post
			global $plugins;
			if(!$pid) {
				// trick system into thinking that this post should be unapproved
				$user['__spamalyser_backup_moderateposts'] = $user['moderateposts'];
				$user['moderateposts'] = 1;
				$plugins->add_hook('datahandler_post_insert_post', 'spamalyser_fix_user_modposts');
				$plugins->add_hook('datahandler_post_insert_thread_post', 'spamalyser_fix_user_modposts');
			} elseif(!$newpost) {
				// wish it were this simple...
				//$data['visible'] = 0;
				
				// can't unapprove immediately, may be cached in get_post
				// defer this action until later
				$plugins->add_hook('datahandler_post_update', 'spamalyser_unapprove_edit');
				// to force in a proper user redirect, encapsulate the posthandler
				// this is a very ugly hack!
				global $posthandler;
				if(is_object($posthandler)) {
					control_object($posthandler, '
						function update_post() {
							static $done = false;
							$ret = parent::update_post();
							if(!$done) {
								$done = true;
								$ret[\'visible\'] = 0;
							}
							return $ret;
						}
					');
					$posthandler->data = $ph->data;
					$posthandler->set_validated(true); // not exactly best practice, but should work okay :/
					// cannot set any values to $ph now, but we don't anyway
				}
			}
			$logentry['actions'] .= ($logentry['actions']?',':'') . 'unapproved';
		}
		
		$db->insert_query('spamalyser_log', $logentry);
		if(!$pid && !isset($double_post)) {
			$log_id = $db->insert_id();
			// need to update log entry when we have the IDs
			global $plugins;
			$plugins->add_hook('datahandler_post_insert_post', 'spamalyser_after_post_hook');
			$plugins->add_hook('datahandler_post_insert_thread_post', 'spamalyser_after_post_hook');
			$ph->spamalyser_logentry = $log_id;
		}
	}
}

// determine the approximate number of Google search results for a query
// doesn't use API, so may break in future
function spamalyser_num_google_results($s) {
	// should we cache these searches?
	$data = fetch_remote_file('http://www.google.com/search?q='.urlencode($s).'&ie='.strtolower($GLOBALS['lang']->settings['charset']).'&oe=utf-8');
	if(preg_match('~\<div id\=resultStats\>About ([0-9,]+) results?\<~', $data, $m)) {
		return str_replace(',', '', $m[1]); // may exceed 32-bit int limits, so don't typecast
	}
	if(strpos($data, '>Your search - <') && strpos($data, '> - did not match any documents.'))
		return 0;
	return false;
}

// intermediary parser - converts all tags to \r and newlines to \n
// TODO: converting all tags is problematic with fake inserted formatting, eg "wo[b][/b]rd"
function spamalyser_parse_msg(&$msg) {
	global $parser;
	if(!is_object($parser)) {
		unset($parser);
		require_once MYBB_ROOT.'inc/class_parser.php';
		$parser = new postParser;
	}
	return html_entity_decode(
		preg_replace(array("~\s*\n\s*~", "~ *\r[ \r]*~"), array("\n", "\r"),
			preg_replace(array('~\<[a-zA-Z0-9:\-_]+(\s+[^>]*?)/?\>~', '~\</[a-zA-Z0-9:\-_]+\>~'), "\r",
				preg_replace(array('~\<br(\s+[^>]*?)?/?\>~i', '~\<p(\s+[^>]*?)?/?\>~i'), array("\n", "\n\n"),
					preg_replace('~\s+~', ' ',
						strtr(
							$parser->parse_message($msg, array('allow_html' => 0, 'allow_smilies' => 1, 'allow_mycode' => 1, 'nl2br' => 1, 'filter_badwords' => 0, 'allow_imgcode' => 1, 'allow_videocode' => 1)),
						array("\r" => '', "\n" => ''))
					)
				)
			)
		), ENT_QUOTES, 'UTF-8'
	);
	// parse MyCode, then strip newlines, then convert remaining whitespaces to space, then convert <br> tags to newlines, then strip tags, then trim other whitespace, and finally html decode
}

// like substr($s, 0, $p), but cuts off at last space before $p
function spamalyser_keyword_trim($s, $p) {
	if(!isset($s[$p])) return $s;
	$s = my_substr($s, 0, $p);
	if($p = strrpos($s, ' ')) $s = substr($s, 0, $p);
	return $s;
}

// like strrpos, but with end position; if length of haystack is <= pos, will return length of haystack; if not found, returns pos
function spamalyser_strrpos($haystack, $needle, $pos) {
	$len = my_strlen($haystack);
	if($len <= $pos) return $len;
	$haystack = my_substr($haystack, 0, $pos);
	
	if(function_exists('mb_strrpos')) $strrpos = 'mb_strrpos';
	else $strrpos = 'strrpos';
	if($p = $strrpos($haystack, $needle)) return $p;
	return $pos; // fallback
	
}

// accumulate domains and keywords - used for past post analysis
function spamalyser_accum_dom_kw($msg, &$domains, &$keywords, &$ignore_links=array()) {
	spamalyser_grab_links_from_post($msg, $links, $keywords, $ignore_links);
	foreach($links as $host => &$link) {
		$domains[$host] += count($link);
	}
}

function spamalyser_calc_msg_weight($msg, &$domains=array(), &$keywords=array(), &$ignore_links=array()) {
	if(!$msg) return 0;
	$settings =& $GLOBALS['mybb']->settings;
	
	$numlinks = spamalyser_grab_links_from_post($msg, $links, $keywords, $ignore_links);
	//if($numlinks < (int)$settings['spamalyser_thresh_links']) return;
	
	$spamalyser_keyword_bad = array_flip(array_map('strtolower', array_map('trim', explode(',', $settings['spamalyser_keyword_bad']))));
	$link_weight = (float)$settings['spamalyser_weight_link'];
	$complexlink_weight = (float)$settings['spamalyser_weight_complexlink'];
	$link_weight_limit = (float)$settings['spamalyser_link_limit'];
	$complexlink_weight_limit = (float)$settings['spamalyser_complexlink_limit'];
	$host_weight = (float)$settings['spamalyser_weight_samehost'];
	$dupeword_weight = (float)$settings['spamalyser_weight_keyword'];
	$badword_weight = (float)$settings['spamalyser_weight_badword'];
	// do weighting calculation
	$postweight = 0;
	foreach($links as $host => &$link) {
		$domains[$host] += count($link);
		$domweight = pow($domains[$host], 1+$host_weight) - $domains[$host] +1;
		foreach($link as $l) {
			list($url, $text, $words) = $l;
			if(isset($text)) {
				$addweight = $complexlink_weight;
				$maxweight = $complexlink_weight_limit;
			} else {
				$addweight = $link_weight;
				$maxweight = $link_weight_limit;
			}
			// keywords
			$addwordweights = 0;
			foreach($words as $word => $wordcnt) {
				$addwordweight = ($wordcnt * (pow($keywords[$word], 1+$dupeword_weight) - $keywords[$word]));
				if(isset($spamalyser_keyword_bad[$word])) {
					// increase the base link weight for each badword occurance
					$addweight *= pow($badword_weight, $wordcnt);
					// also increase the weight of this word (to further punish if the user duplicates it)
					$addwordweight *= $badword_weight;
				}
				$addwordweights += $addwordweight;
			}
			$addweight = ($addweight + $addwordweights) * $domweight;
			if($maxweight) $addweight = min($addweight, $maxweight);
			$postweight += $addweight;
		}
	}
	
	return $postweight;
}

function spamalyser_grab_links_from_post($msg, &$links, &$keywords, &$ignore_links=array()) {
	if(!$msg) return 0;
	$settings =& $GLOBALS['mybb']->settings;
	// completely remove code/php boxes (as links aren't parsed in them), as well as images
	$exttags = (function_exists('coolcode_run') ? '|c|cpp|java|js|bat|sql|vb|html|xml|ini':''); // Syntax Highlighter plugin
	$pfind = array('~\[(code|php'.$exttags.')\](.*?)\[/\\1\]~si', '~\[img(?:\=[0-9]{1,3}x[0-9]{1,3})?(?: align\=[a-z]+)?\]https?\://([^<>"\']+?)\[/img\]~si');
	$prepl = array('','');
	if($GLOBALS['mybb']->version_code >=1500) {
		$pfind[] = '~\[video(\=[a-z]+)?\]https?\://([^<>"\']+?)\[/video\]~i';
		$prepl[] = '';
	}
	$msg = preg_replace($pfind, $prepl, $msg);
	
	// find links in post - if none, bail
	// TODO: check if MyCode is enabled and maybe try detect HTML links as well?
	// TODO: and/or maybe consider actually parsing the message and grabbing output instead? for now, we'll assume spammers aren't clever enough to use URLs other than [url] tags
	$links_simple = spamalyser_preg_match_remove('~\[url\]([^\r\n"<]+?)\[/url\]~is', $msg);
	$links_complex = spamalyser_preg_match_remove('~\[url=([^\r\n"<&\(\)]+?|[a-z]+?\://[^\r\n"<]+?)\](.+?)\[/url\]~is', $msg);
	// not exactly the way MyBB detects auto-links, but spambots aren't that clever are they?
	$links_auto = spamalyser_preg_match_remove('~(?<=[^a-z0-9])((https?\://|www\.|ftp\.)([@a-z0-9\-.]+)(\:\d+)?(/[^"\s<\[\]]*)?)~i', $msg);
	
	// build array of linked text/urls and do domain counts in the process
	isset($links) or $links = array();
	isset($keywords) or $keywords = array();
	static $init=false;
	static $safe_hosts;
	if(!$init) {
		$init = true;
		$GLOBALS['spamalyser_keyword_minlen'] = (int)$settings['spamalyser_keyword_minlen'];
		$GLOBALS['spamalyser_keyword_safe'] = array_flip(array_map('strtolower', array_map('trim', explode(',', $settings['spamalyser_keyword_safe']))));
		
		$safe_hosts = spamalyser_parse_host_list($settings['spamalyser_safe_hosts']);
	}
	if(!empty($links_simple)) foreach($links_simple[1] as &$link) {
		if(isset($ignore_links[$link])) continue;
		spamalyser_run_addlink($links, $keywords, $link);
	} unset($link);
	if(!empty($links_auto)) foreach($links_auto[1] as &$link) {
		if(isset($ignore_links[$link])) continue;
		spamalyser_run_addlink($links, $keywords, $link);
	} unset($link);
	if(!empty($links_complex)) foreach($links_complex[1] as $k => &$url) {
		if(isset($ignore_links[$url])) continue;
		// complex link -> we need to also strip out MyCode
		$newtext = $links_complex[2][$k];
		do {
			$text = $newtext;
			$newtext = preg_replace(array(
				'~\[(hr|\*)\]~i',
				'~\[(b|i|u|s|list)\](.*?)\[/\\1\]~i',
				'~\[(font|quote|size|color|align|list)\=[^]"]+?\](.*?)\[/\\1\]~i',
			), array('', '$2', '$2'), $text);
		} while($newtext != $text);
		spamalyser_run_addlink($links, $keywords, $url, $text);
	} unset($url);
	
	// remove safe hosts
	$numlinks = 0;
	foreach($links as $host => &$link) {
		$host_l = strtolower($host);
		$numlinks += count($link);
		// loop-in-loop; there are possible ways to make this faster, but unnecessary IMO
		foreach($safe_hosts as &$safe_host) {
			if(preg_match($safe_host, $host_l)) {
				$numlinks -= count($link);
				unset($links[$host]);
				break;
			}
		}
	}
	return $numlinks;
}
function &spamalyser_preg_match_remove($regex, &$msg) {
	preg_match_all($regex, $msg, $matches);
	if(!empty($matches))
		$msg = preg_replace($regex, '', $msg);
	return $matches;
}

function spamalyser_run_addlink(&$links, &$keywords, $url, $text=null) {
	if(!preg_match('~^[a-zA-Z0-9]+\://~', $url))
		$url = 'http://'.$url;
	
	// grab domain
	$purl = @parse_url($url);
	if($purl === false) return; // malformed URL, ignore in spam analysis
	$host =& $purl['host'];
	if(!isset($links[$host]))
		$links[$host] = array();
	
	// keywords
	if(isset($text)) {
		$kwtext = $text;
		$kwtexturl = '';
	} else {
		$kwtext = '';
		$kwtexturl = $purl['host']; // include host for simple link because we assume that if a spammer is posting simple links, chances are that the keywords are in the link
	}
	if($purl['path']) $kwtexturl .= ' '.$purl['path'];
	if($purl['query']) $kwtexturl .= ' '.$purl['query'];
	$kwtexturl = trim($kwtexturl);
	
	$words = array();
	if($kwtext) {
		foreach(spamalyser_keywords_from_text($kwtext) as $word => $count) {
			(isset(   $words[$word])) ?    $words[$word] += $count :    $words[$word] = $count;
			(isset($keywords[$word])) ? $keywords[$word] += $count : $keywords[$word] = $count;
		}
	}
	if(isset($text) && empty($words)) {
		// complex link, but all keywords are "safe" - we'll consider this as a normal non-complex link
		$text = null;
		$kwtexturl = trim($purl['host'].' '.$kwtexturl);
	}
	if($kwtexturl) {
		// we'll accumulate keywords in the URL, but won't consider them keywords for the actual link
		foreach(spamalyser_keywords_from_text($kwtexturl) as $word => $count) {
			(isset($keywords[$word])) ? $keywords[$word] += $count : $keywords[$word] = $count;
		}
	}
	
	$links[$host][] = array($url, $text, $words);
}
function &spamalyser_keywords_from_text($s) {
	$words = array();
	// we use this matching sequence instead of \W because \W can match foreign characters in various unicode encodings (we'll ignore the fact that MyBB's badword filter is messed up because of this); essentially, this is like \W, but ignores some characters below 0x20, and anything above 0x7f (since this is a common encoding nightmare ground)
	// this obviously won't pick up "unicode spaces"
	foreach(explode(' ', 
		trim(preg_replace('~[\s\x20-\x2f\x3a-\x40\x5b-\x60\x7b-\x7f]+~', ' ', strtolower($s)))
	) as $word) {
		if(my_strlen($word) < $GLOBALS['spamalyser_keyword_minlen'])
			continue;
		if(isset($GLOBALS['spamalyser_keyword_safe'][$word]) || is_numeric($word)) // all numbers, such as "2011" aren't considered keywords
			continue;
		(isset(   $words[$word])) ?    ++$words[$word] :    $words[$word] = 1;
	}
	return $words;
}

// parses a host list into regex
function &spamalyser_parse_host_list($list) {
	$hosts = array_map('strtolower', array_map('trim', explode(',', strtr($list, array("\r" => '', "\n" => ',')))));
	foreach($hosts as $k => &$host) {
		if($host === '') {
			unset($hosts[$k]);
			continue;
		}
		$host = '~^(?:[a-z0-9\\-.]+\.)?'.strtr(preg_quote($host, '~'), array('\\*' => '[a-z0-9\\-]+', '\\{COM\\}' => '(?:com?\.)?[a-z0-9\\-]{2,5}')).'$~s';
	}
	return $hosts;
}

// grab a list of links from quoted posts
function &spamalyser_grab_quote_links(&$msg, $pid=0) {
	$ret = array();
	$opt = $GLOBALS['mybb']->settings['spamalyser_ignore_quotelinks'];
	if($opt != 'safe' && $opt != 'any') $opt = 'off';
	if(!$msg || $opt == 'off') return $ret;
	
	// read quoted pids from post
	$pids = array();
	preg_match_all('~\[quote\=(?:[^\]"<>]+?|"[^"]+")[^\]]*? pid\=(["\'])?(\d+)\\1[^\]]*?\]~i', $msg, $matches);
	if(!empty($matches[2]))
		foreach($matches[2] as $mpid)
			$pids[(int)$mpid] = 1;
	
	if(function_exists('vbquote_info')) { // vB Quote plugin
		preg_match_all('~\[quote\=(?:[^\]"<>]+?|"[^"]+");(\d+)\]~i', $msg, $matches);
		if(!empty($matches[1]))
			foreach($matches[1] as $mpid)
				$pids[(int)$mpid] = 1;
	}
	
	if($pid) unset($pids[$pid]); // if quoting own post...
	
	// grab referred posts - we won't consider permissions since user can't actually extract useful info this way (well, feasibly at least)
	if(empty($pids)) return $ret;
	$pids = array_keys($pids);
	if(count($pids) > 50) $pids = array_slice($pids, 0, 50); // hard limit
	global $db;
	if($opt == 'any')
		$query = $db->simple_select('posts', 'uid,message', 'pid IN ('.implode(',', $pids).')');
	else
		$query = $db->query('
			SELECT p.uid, p.message, u.timeonline, u.regdate, u.totalpms, u.postnum, u.usergroup
			FROM '.TABLE_PREFIX.'posts p
			LEFT JOIN '.TABLE_PREFIX.'users u ON p.uid=u.uid
			WHERE p.pid IN ('.implode(',', $pids).')
		');
	while($post = $db->fetch_array($query)) {
		if($opt == 'safe' && !spamalyser_check_user_thresh($post)) continue; // skip "unsafe" quotes if option enabled
		// note that we don't need to remove matched links because this doesn't mind dupes
		// scan for links in posts
		preg_match_all('~\[url\]([^\r\n"<]+?)\[/url\]~is', $post['message'], $links);
		if(!empty($links)) foreach($links[1] as &$link) {
			$ret[$link] = 1;
		} unset($link, $links);
		
		preg_match_all('~\[url=([^\r\n"<&\(\)]+?|[a-z]+?\://[^\r\n"<]+?)\].+?\[/url\]~is', $post['message'], $links);
		if(!empty($links)) foreach($links[1] as &$link) {
			$ret[$link] = 1;
		} unset($link, $links);
		
		preg_match_all('~(?:[\>\s\(\)])((https?\://[^\/"\s\<\[\.]+|www|ftp)\.([^\/"\s\<\[\.]+\.)*[\w]+(\:[0-9]+)?(/[^"\s<\[]*)?)~i', ' '.$post['message'], $links);
		if(!empty($links)) foreach($links[1] as &$link) {
			$ret[$link] = 1;
		} unset($link, $links);
	}
	$db->free_result($query);
	return $ret;
}

function spamalyser_after_post_hook(&$ph) {
	global $plugins;
	$plugins->remove_hook('datahandler_post_insert_post', 'spamalyser_after_post_hook');
	$plugins->remove_hook('datahandler_post_insert_thread_post', 'spamalyser_after_post_hook');
	
	control_object($GLOBALS['db'], '
		function insert_query($table, $array) {
			static $done=false;
			if(!$done && $table == "posts") {
				$done=true;
				$pid = parent::insert_query($table, $array);
				_spamalyser_after_post_hook($pid, $this->spamalyser_ph);
				return $pid;
			}
			return parent::insert_query($table, $array);
		}
	');
	$GLOBALS['db']->spamalyser_ph =& $ph;
}
function _spamalyser_after_post_hook($pid, &$ph) {
	// report post if necessary
	if(isset($ph->data['spamalyser_postweight'])) {
		if(spamalyser_report_post($pid, $ph->data['spamalyser_postweight'])) {
			$update_actions = $ph->data['spamalyser_actions'];
			$update_actions .= ($update_actions?',':'') . 'reported';
		}
		unset($ph->data['spamalyser_postweight'], $ph->data['spamalyser_postweight']);
	}
	// update log
	if($ph->spamalyser_logentry) {
		$update = array('pid' => $pid);
		if(isset($update_actions)) $update['actions'] = $update_actions;
		if($ph->tid) $update['tid'] = $ph->tid;
		$GLOBALS['db']->update_query('spamalyser_log', $update, 'lid='.$ph->spamalyser_logentry);
		unset($ph->spamalyser_logentry);
	}
}


// TODO: support other reporting mechanisms
function spamalyser_report_post($pid, $thresh) {
	global $db, $lang;
	$pid = (int)$pid;
	$settings =& $GLOBALS['mybb']->settings;
	if($settings['spamalyser_report_nodupe']) {
		// check for attached unread reports
		if($db->fetch_field($db->simple_select('reportedposts', 'rid', 'pid='.$pid.' AND reportstatus=0', array('limit' => 1)), 'rid')) return false;
	}
	$lang->load('spamalyser');
	$post = get_post($pid);
	$db->insert_query('reportedposts', array(
		'pid' => $pid,
		'tid' => $post['tid'],
		'fid' => $post['fid'],
		'uid' => (int)$settings['spamalyser_report_uid'],
		'dateline' => TIME_NOW,
		'reportstatus' => 0,
		'reason' => $db->escape_string($lang->sprintf($lang->spamalyser_report_msg, $thresh))
	));
	$GLOBALS['cache']->update_reportedposts();
	return true;
}

function spamalyser_fix_user_modposts() {
	global $plugins;
	$plugins->remove_hook('datahandler_post_insert_post', 'spamalyser_fix_user_modposts');
	$plugins->remove_hook('datahandler_post_insert_thread_post', 'spamalyser_fix_user_modposts');
	
	$user =& $GLOBALS['mybb']->user;
	$user['moderateposts'] = $user['__spamalyser_backup_moderateposts'];
	unset($user['__spamalyser_backup_moderateposts']);
	
	global $lang;
	$lang->load('spamalyser');
	$lang->redirect_newthread_moderation = $lang->spamalyser_redirect_newthread_spam_blocked;
	$lang->redirect_newreply_moderation = $lang->spamalyser_redirect_newreply_spam_blocked;
}
function spamalyser_unapprove_edit(&$ph) {
	require_once MYBB_ROOT.'inc/class_moderation.php';
	$moderation = new Moderation;
	$moderation->unapprove_posts(array($ph->data['pid']));
	
	$ph->post_update_data['visible'] = 0;
	$GLOBALS['plugins']->remove_hook('datahandler_post_update', 'spamalyser_unapprove_edit');
	
	// update lang messages
	global $lang;
	$lang->load('spamalyser');
	$lang->redirect_thread_moderation = $lang->spamalyser_redirect_newthread_spam_blocked;
	$lang->redirect_post_moderation = $lang->spamalyser_redirect_newreply_spam_blocked;
}

function &spamalyser_get_http_headers() {
	$ret = $_SERVER['REQUEST_METHOD'].' '.$_SERVER['REQUEST_URI'].' '.$_SERVER['SERVER_PROTOCOL']."\r\n";
	
	// do HTTP headers have any special escape sequences?
	
	if(function_exists('apache_request_headers') && ($headers = apache_request_headers()))
		foreach($headers as $k => &$v) {
			$ret .= $k.': '.$v."\r\n";
		}
	else
		foreach($_SERVER as $k => &$v) {
			if(substr($k, 0, 5) == 'HTTP_') {
				$k = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($k, 5)))));
				$ret .= $k.': '.$v."\r\n";
			}
		}
	
	return $ret;
}

// TODO: trigger notification on signature change?


/* function ip2bin($ip) {
	return decbin(ip2long($ip));
} */

if(!function_exists('control_object')) {
	function control_object(&$obj, $code) {
		static $cnt = 0;
		$newname = '_objcont_'.(++$cnt);
		$objserial = serialize($obj);
		$classname = get_class($obj);
		$checkstr = 'O:'.strlen($classname).':"'.$classname.'":';
		$checkstr_len = strlen($checkstr);
		if(substr($objserial, 0, $checkstr_len) == $checkstr) {
			$vars = array();
			// grab resources/object etc, stripping scope info from keys
			foreach((array)$obj as $k => $v) {
				if($p = strrpos($k, "\0"))
					$k = substr($k, $p+1);
				$vars[$k] = $v;
			}
			if(!empty($vars))
				$code .= '
					function ___setvars(&$a) {
						foreach($a as $k => &$v)
							$this->$k = $v;
					}
				';
			eval('class '.$newname.' extends '.$classname.' {'.$code.'}');
			$obj = unserialize('O:'.strlen($newname).':"'.$newname.'":'.substr($objserial, $checkstr_len));
			if(!empty($vars))
				$obj->___setvars($vars);
		}
		// else not a valid object or PHP serialize has changed
	}
}

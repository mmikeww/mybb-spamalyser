<?php

defined('IN_MYBB') or die('This file cannot be accessed directly.');

if(defined('IN_ADMINCP')) {
	require MYBB_ROOT.'inc/plugins/spamalyser/sp_admin.php';
} else {
	// only add our hooks on certain pages to avoid issues with stuff such as RSS posters etc
	// (I guess, on the other hand, we miss other methods users may post, but that can be added later if necessary)
	$plugins->add_hook('xmlhttp', 'spamalyser_addhooks');
	$plugins->add_hook('newthread_do_newthread_start', 'spamalyser_addhooks');
	$plugins->add_hook('newreply_do_newreply_start', 'spamalyser_addhooks');
	$plugins->add_hook('editpost_start', 'spamalyser_addhooks');
	
	function spamalyser_addhooks() {
		global $plugins;
		$plugins->add_hook('datahandler_post_validate_thread', 'spamalyser_newpost', 10);
		$plugins->add_hook('datahandler_post_validate_post', 'spamalyser_checks', 99999999);
	}
	
	function spamalyser_newpost(&$ph) {
		return spamalyser_checks($ph, true);
	}
	function spamalyser_checks(&$ph, $newthread=false) {
		// check exclusions before loading full core - for the typical forum, this should give a performance boost
		$settings =& $GLOBALS['mybb']->settings;
		$user =& $GLOBALS['mybb']->user;
		$data =& $ph->data;
		$postuid = (int)$data['uid'];
		if(!$newthread) $newpost = ($ph->method == 'insert');
		else $newpost = true;
		$pid = (int)$data['pid'];
		$tid = (int)$data['tid'];
		$fid = (int)$data['fid'];
		if(!$newpost && $pid) {
			$post = get_post($pid); // cached fetch
			if(!$postuid) $postuid = $post['uid'];
		}
		if(!$fid) {
			// this needs to be set...
			if($tid) {
				$thread = get_thread($tid);
				$fid = $thread['fid'];
			} elseif($pid) {
				$post = get_post($pid);
				$fid = $post['fid'];
			}
		}
		
		// if this is a moderator edit, bail
		if($user['uid'] != $postuid) return;
		// or a moderator...
		if(is_moderator($fid, '', $user['uid'])) return;
		
		// updating post and message not sent - don't need to check anything
		if(!$newpost && !$data['message']) return;
		
		// saving draft, don't bother calculating spam weighting
		if($data['savedraft']) return;
		
		
		$postcount_incr = false;
		if($newpost && $tid) {
			$forum = get_forum($tid);
			if($forum['usepostcounts'] != 0) $postcount_incr = true;
		}
		if(spamalyser_check_user_thresh($user, $postcount_incr)) return;
		
		$postcount = max($user['postnum'], 0) + ($postcount_incr ? 1:0);
		
		// if there's errors and post won't go through, don't bother with calculation
		if(!empty($ph->errors)) return;
		
		// go on and calculate weightings
		require_once MYBB_ROOT.'inc/plugins/spamalyser/sp_main.php';
		spamalyser_run($ph, $newthread, $newpost, $fid, $postcount);
	}
	
	// check if user exceeds checking thresholds; returns true if so (that is, user is "safe")
	function spamalyser_check_user_thresh(&$user, $postcount_incr=false) {
		$settings =& $GLOBALS['mybb']->settings;
		if($user['uid']) {
			if(($thresh_onlinetime = (float)$settings['spamalyser_thresh_onlinetime'])
				&& max($user['timeonline']/60, 0) > $thresh_onlinetime) return true;
			if(($thresh_regtime = (float)$settings['spamalyser_thresh_regtime'])
				&& max((TIME_NOW - $user['regdate'])/3600, 0) > $thresh_regtime) return true;
			if(($thresh_pms = (int)$settings['spamalyser_thresh_pms']) && $user['totalpms'] > $thresh_pms) return true;
			if((int)$settings['spamalyser_thresh_postcount'] < max($user['postnum'], 0) + ($postcount_incr ? 1:0)) return true;
		}
		if(!in_array($user['usergroup'], array_map('intval', array_map('trim', explode(',', $settings['spamalyser_groups']))))) return true;
		return false;
	}
	
}

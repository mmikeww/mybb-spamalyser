<?php
defined('IN_MYBB') or die('Direct initialization of this file is not allowed.');

define('SPAMALYSER_URL', 'index.php?module=tools'.($mybb->version_code>=1500?'-':'/').'spamalyserlog');

$page->add_breadcrumb_item($lang->spamalyser_logs, SPAMALYSER_URL);

$sub_tabs['spamalyser_logs'] = array(
	'title' => $lang->spamalyser_logs,
	'link' => SPAMALYSER_URL,
	'description' => $lang->spamalyser_logs_desc
);
$sub_tabs['prune_spamalyser_logs'] = array(
	'title' => $lang->prune_spamalyser_logs,
	'link' => SPAMALYSER_URL.'&amp;action=prune',
	'description' => $lang->prune_spamalyser_logs_desc
);


// build the forum >> thread >> post path from a logitem
function spamalyser_build_post_path(&$logitem) {
	global $lang, $forums, $mybb;
	$bburl = htmlspecialchars_uni($mybb->settings['bburl'].'/');
	$subject = htmlspecialchars_uni($logitem['subject']);
	if($logitem['real_pid'])
		$subject = '<a href="'.$bburl.get_post_link($logitem['pid'], $logitem['tid']).'#pid'.$logitem['pid'].'" target="_blank">'.$subject.'</a>';
	if($logitem['threadsubject']) {
		if($logitem['real_tid'])
			$subject = '<a href="'.$bburl.get_thread_link($logitem['tid']).'" target="_blank">'.htmlspecialchars_uni($logitem['threadsubject']).'</a> &raquo; '.$subject;
		else
			$subject = htmlspecialchars_uni($logitem['threadsubject']).' &raquo; '.$subject;
	}
	if(empty($forums))
		$forums = $GLOBALS['cache']->read('forums');
	if($forums[$logitem['fid']]) {
		$subject = '<a href="'.$bburl.get_forum_link($logitem['fid']).'" target="_blank">'.$forums[$logitem['fid']]['name'].'</a> &raquo; '.$subject;
	}
	// new/edit icons
	if($logitem['event'] == 0)
		$subject = '<img src="spamalyser_img/post_new.gif" title="'.$lang->icon_new_thread_post.'" alt="'.$lang->icon_alt_new_thread_post.'" style="margin-right: 0.5em; font-size: smaller; vertical-align: middle;" />'.$subject;
	elseif($logitem['event'] == 2)
		$subject = '<img src="spamalyser_img/post_merge.gif" title="'.$lang->icon_merge_post.'" alt="'.$lang->icon_alt_merge_post.'" style="margin-right: 0.5em; font-size: smaller; vertical-align: middle;" />'.$subject;
	else
		$subject = '<img src="spamalyser_img/post_edit.gif" title="'.$lang->icon_edit_thread_post.'" alt="'.$lang->icon_alt_edit_thread_post.'" style="margin-right: 0.5em; font-size: smaller; vertical-align: middle;" />'.$subject;
	return $subject;
}

$plugins->run_hooks('admin_tools_spamalyserlog_begin');

$lang->load('tools_modlog'); // borrow some phrases from here

if($mybb->input['action'] == 'prune') {
	if($mybb->request_method == 'post') {
		$datecut = (int)$mybb->input['older_than'];
		if(!$datecut) $datecut = 30;
		$where = 'dateline < '.(TIME_NOW - $datecut*86400);
		
		// Searching for entries by a particular user
		//if($mybb->input['uid'])
		//	$where .= " AND uid='".intval($mybb->input['uid'])."'";
		// score pruning?
		
		$db->delete_query('spamalyser_log', $where);
		$num_deleted = $db->affected_rows();
		
		$plugins->run_hooks('admin_tools_spamalyserlog_prune_commit');
		
		// Log admin action
		log_admin_action($datecut, $num_deleted);

		flash_message($lang->success_pruned_spamalyser_logs, 'success');
		admin_redirect(SPAMALYSER_URL);
	}
	$page->add_breadcrumb_item($lang->prune_spamalyser_logs, SPAMALYSER_URL.'&amp;action=prune');
	$page->output_header($lang->prune_spamalyser_logs);
	$page->output_nav_tabs($sub_tabs, 'prune_spamalyser_logs');
	
	$form = new Form(SPAMALYSER_URL.'&amp;action=prune', 'post');
	$form_container = new FormContainer($lang->prune_spamalyser_logs);
	if(!$mybb->input['older_than'])
		$mybb->input['older_than'] = '30';
	$form_container->output_row($lang->date_range, '', $lang->older_than.$form->generate_text_box('older_than', (int)$mybb->input['older_than'], array('id' => 'older_than', 'style' => 'width: 30px')).' '.$lang->days, 'older_than');
	$form_container->end();
	$form->output_submit_wrapper(array($form->generate_submit_button($lang->prune_spamalyser_logs)));
	$form->end();
	
	$page->output_footer();
}

if($mybb->input['action'] == 'view') {
	$logitem = $db->fetch_array($db->simple_select('spamalyser_log', '*', 'lid='.(int)$mybb->input['lid']));
	if(empty($logitem)) {
		flash_message($lang->error_invalid_logitem, 'error');
		admin_redirect(SPAMALYSER_URL);
	}
	$page->add_breadcrumb_item($lang->view_spamalyser_logitem, SPAMALYSER_URL.'&amp;action=view&amp;lid='.$logitem['lid']);
	$page->output_header($lang->spamalyser_logs);
	$page->output_nav_tabs($sub_tabs, 'spamalyser_logs');
	
	
	$post_test = get_post($logitem['pid']);
	if(!empty($post_test)) {
		$logitem['real_pid'] = $post_test['pid'];
		$logitem['real_tid'] = $post_test['tid'];
	} else {
		$thread_test = get_thread($logitem['tid']);
		if(!empty($thread_test)) $logitem['real_tid'] = $thread_test['tid'];
	}
	
	$table = new Table;
	$numcell_style = array('style' => 'text-align: right;', 'width' => '30%');
	$table->construct_header($lang->weighting_component);
	$table->construct_header($lang->weighting_amount, array('class' => 'align_center'));
	$det = @unserialize($logitem['details']);
	if(!is_array($det)) $det = array();
	foreach($det as $k => $v) {
		$langkey = 'weighting_'.$k;
		if($lang->$langkey)
			$table->construct_cell($lang->$langkey);
		else
			$table->construct_cell($k);
		$table->construct_cell(number_format($v, 7), $numcell_style);
		$table->construct_row();
	}
	$table->construct_cell('<strong>'.$lang->weighting_overall.'</strong>');
	$table->construct_cell(number_format($logitem['score'], 7), $numcell_style);
	$table->construct_row();
	$table->output($lang->weighting_calculation);
	
	echo '<a id="post"></a>';
	$table = new Table;
	$table->construct_cell(spamalyser_build_post_path($logitem));
	$table->construct_row();
	$table->construct_cell(nl2br(htmlspecialchars_uni($logitem['message'])));
	$table->construct_row();
	$table->output($lang->post_message);
	
	$table = new Table;
	$table->construct_cell('<strong>'.$lang->request_ip.'</strong>: '.htmlspecialchars($logitem['ipaddress']));
	$table->construct_row();
	$table->construct_cell(nl2br(htmlspecialchars($logitem['httpreq'])));
	$table->construct_row();
	$table->output($lang->http_info);
	
	$page->output_footer();
}

if(!$mybb->input['action']) {
	$page->output_header($lang->spamalyser_logs);
	$page->output_nav_tabs($sub_tabs, 'spamalyser_logs');
	
	$where = $urlargs = '';
	if($mybb->input['uid']) {
		$uid = (int)$mybb->input['uid'];
		$where .= ' AND l.uid='.$uid;
		$urlargs .= '&amp;uid='.$uid;
	}
	if($mybb->input['score'] && $mybb->input['scorecmp']) {
		$score = (float)$mybb->input['score'];
		$scorecmp = (strtolower($mybb->input['scorecmp']) == 'lte' ? 'lte':'gte');
		$where .= ' AND l.score'.($scorecmp == 'lte' ? '<=':'>=').$score;
		$urlargs .= '&amp;score='.$score.'&amp;scorecmp='.$scorecmp;
	}
	
	switch($sortby = strtolower($mybb->input['sortby'])) {
		case 'username':
			$sortby = 'u.'.$sortby;
			break;
		case 'score':
			$sortby = 'l.'.$sortby;
			break;
		default:
			$sortby = 'l.dateline';
	}
	$order = ($mybb->input['order'] == 'asc' ? 'asc':'desc');
	
	if($mybb->input['sortby'])
		$urlargs .= '&amp;sortby='.$sortby;
	if($mybb->input['order'])
		$urlargs .= '&amp;order='.$order;
	
	// paging
	$perpage = 20;
	if($mybb->input['perpage']) {
		$perpage = (int)$mybb->input['perpage'];
		if($perpage < 1) $perpage = 20;
		$urlargs .= '&amp;perpage='.$perpage;
	}
	
	$entries = $db->fetch_field($db->simple_select('spamalyser_log', 'COUNT(*) AS c', $where), 'c');
	$pages = ceil($entries / $perpage);
	$pagenum = min($pages, max(1, 
		($mybb->input['page'] == 'last' ? $pages : (int)$mybb->input['page'])
	));

	$table = new Table;
	$lang_post = $lang->post;
	if(substr($lang_post, -1) == ':') $lang_post = substr($lang_post, 0, -1);
	$table->construct_header($lang->username, array('width' => '15%'));
	$table->construct_header($lang->date, array('class' => 'align_center', 'width' => '15%'));
	$table->construct_header($lang_post, array('width' => '55%'));
	$table->construct_header($lang->weighting, array('class' => 'align_center', 'width' => '15%'));

	if($entries) {
		//$query = $db->simple_select('spamalyser_log', '*', '1=1 '.$where, array('order_by' => $sortby, 'order_dir' => $order, 'limit_start' => (($page-1)*$perpage), 'limit' => $perpage));
		$qx = (function_exists('softdelete_showthread') ? ' p.deleted AS post_deleted, t.deleted AS thread_deleted,':''); // SoftDelete plugin
		$query = $db->query('
			SELECT l.*, p.pid AS real_pid, p.visible,'.$qx.' t.tid AS real_tid, u.uid AS real_uid, u.usergroup, u.displaygroup
			FROM '.TABLE_PREFIX.'spamalyser_log l
			LEFT JOIN '.TABLE_PREFIX.'posts p ON (p.pid=l.pid)
			LEFT JOIN '.TABLE_PREFIX.'threads t ON (t.tid=l.tid)
			LEFT JOIN '.TABLE_PREFIX.'users u ON (u.uid=l.uid)
			WHERE 1=1 '.$where.'
			ORDER BY '.$sortby.' '.$order.'
			LIMIT '.(($pagenum-1)*$perpage).', '.$perpage
		);
		while($logitem = $db->fetch_array($query)) {
			$information = '';
			$trow = alt_trow();
			
			$username = $logitem['username'];
			if($logitem['uid']) {
				if($logitem['real_uid'])
					//$username = build_profile_link($username, $logitem['uid']);
					$username = '<a href="index.php?module=user'.($mybb->version_code>=1500?'-':'/').'users&amp;action=edit&amp;uid='.$logitem['uid'].'">'.format_name($username, $logitem['usergroup'], $logitem['displaygroup']).'</a>';
			} else {
				// post made by guest
				if($username === '') $username = $lang->guest;
				$username = '<em>'.$username.'</em>';
			}
			$table->construct_cell($username);
			
			$table->construct_cell(date('jS M Y, G:i', $logitem['dateline']), array('class' => 'align_center'));
			
			$subject = spamalyser_build_post_path($logitem);
			// strip excessive (>2) consecutive newlines from message
			$msg = preg_replace("~(\r?\n[ \t\r]*){2,}\n~", "\n\n", trim($logitem['message']));
			$msg_cutoff = 200;
			// limit message to 5 lines (4 newline chars)
			if(preg_match("~^(.*?\n){5}~", $msg, $m)) {
				$msg_cutoff = my_strlen($m[0]) +1; // +1 for good measure :P
				if($msg_cutoff <= 200)
					$msg .= '  '; // silly hack to force next conditional to work
				else
					$msg_cutoff = 200;
			}
			if(my_strlen($msg) > $msg_cutoff)
				$msg = htmlspecialchars_uni(my_substr($msg, 0, $msg_cutoff-1)).'<a href="'.SPAMALYSER_URL.'&amp;action=view&amp;lid='.$logitem['lid'].'#post" title="'.$lang->view_full_post.'">...</a>';
			else
				$msg = htmlspecialchars_uni($msg);
			
			$post_status = '';
			if(!$logitem['real_pid'] || $logitem['post_deleted'] || $logitem['thread_deleted'])
				$post_status = '<img src="spamalyser_img/post_deleted.gif" title="'.$lang->icon_post_deleted.'" alt="" style="float: right; margin-left: 0.5em; margin-top: -2px;" />';
			elseif($logitem['visible'] == 0)
				$post_status = '<img src="spamalyser_img/post_unapproved.gif" title="'.$lang->icon_post_unapproved.'" alt="" style="float: right; margin-left: 0.5em; margin-top: -2px;" />';
			$table->construct_cell($subject.'<br /><span style="font-size: smaller;">'.nl2br(trim($msg)).'</span>'.$post_status);
			
			// generate action icons
			$actions = '';
			$action_array = explode(',', $logitem['actions']);
			asort($action_array);
			foreach($action_array as &$action) {
				//if($action == 'automerge') continue;
				$lang_title = 'icon_action_'.$action;
				$lang_alt = 'icon_action_'.$action.'_alt';
				$actions .= '<img src="spamalyser_img/action_'.$action.'.gif" title="'.$lang->$lang_title.'" alt="'.$lang->$lang_alt.'" style="font-size: smaller;" />';
			}
			if($actions) $actions = '<br />'.$actions;
			$table->construct_cell('<a href="'.SPAMALYSER_URL.'&amp;action=view&amp;lid='.$logitem['lid'].'">'.number_format($logitem['score'], 7).'</a>'.$actions, array('class' => 'align_center'));
			
			$table->construct_row();
		}
	}
	
	if($table->num_rows() == 0)
	{
		$table->construct_cell($lang->no_spamalyserlogs, array('colspan' => '4'));
		$table->construct_row();
	}
	
	$table->output($lang->spamalyser_logs);
	
	if($pages > 1)
		echo draw_admin_pagination($pagenum, $perpage, $entries, SPAMALYSER_URL.$urlargs).'<br />';
	
	// HTML display
	$sortbysel = array($sortby => ' selected="selected"');
	$ordersel = array($order => ' selected="selected"');
	$scorecmpsel = array($scorecmp => ' selected="selected"');
	
	$form = new Form('index.php', 'get');
	echo $form->generate_hidden_field('module', 'tools'.($mybb->version_code>=1500?'-':'/').'spamalyserlog');
	$form_container = new FormContainer($lang->filter_spamalyser_logs);
	$form_container->output_row($lang->sort_by, '', $form->generate_select_box(
		'sortby', array(
			'dateline' => $lang->date,
			'username' => $lang->username,
			'score' => $lang->weighting,
		), $sortby, array('id' => 'sortby')
	).' '.$lang->in.' '.$form->generate_select_box(
		'order', array(
			'asc' => $lang->asc,
			'desc' => $lang->desc
		), $order, array('id' => 'order')
	).' '.$lang->order, 'order');
	$form_container->output_row($lang->results_per_page, '', $form->generate_text_box('perpage', $perpage, array('id' => 'perpage')), 'perpage');

	$form_container->end();
	$form->output_submit_wrapper(array($form->generate_submit_button($lang->filter_spamalyser_logs)));
	$form->end();
	
	$page->output_footer();
}

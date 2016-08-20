<?php

function task_spamalyser_prunelog(&$task) {
	global $db, $lang;
	
	$datecut = 180; // default to 6 months
	
	$db->delete_query('spamalyser_log', 'dateline < '.(TIME_NOW - $datecut*86400));
	$count = $db->affected_rows();
	
	// we'll also prune the SFS cache
	$db->delete_query('spamalyser_sfs_cache', 'lastcheck <= '.(TIME_NOW - 86400));
	
	// setting "isdatahandler" to true is destructive!!!
	if(!$lang->task_spamalyserlog_run_done) $lang->load('spamalyser', true);
	if($count)
		add_task_log($task, $lang->sprintf($lang->task_spamalyserlog_run_cleaned, $count));
	else
		add_task_log($task, $lang->task_spamalyserlog_run_done);
	
}

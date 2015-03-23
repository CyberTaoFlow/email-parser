<?php
// include the graph queries
include 'inc/index-queries.php';
include 'inc/index-functions.php';

// UTC is where we work
date_default_timezone_set('UTC');
// formatting the delta from now->the last input
$datenow = new DateTime();
// OOP method to force the $lastinput var to a DateTime object
// $lastinput comes from inc/index-queries.php
$datelastinput = new DateTime($lastinput);
$interval = $datenow->diff($datelastinput);
$lastinputago = $interval->format('%d days %h hours %i minutes %S seconds');

// gets current usages from inc/index-functions.php
$currenthddusage = get_disk_usage("/");
$currentmemusage = get_server_memory_usage();
$currentcpuusage = get_server_cpu_usage();
?>
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
	<meta name="description" content="">
	<meta name="author" content="">
	<link rel="shortcut icon" href="images/favicon.png" type="image/png">

	<title>[email-parser.py]</title>
	<link href="css/style.default.css" rel="stylesheet">
	<link href="css/morris.css" rel="stylesheet">
	<link href="css/style.katniss.css" rel="stylesheet">
	<link href="css/dropzone.css" rel="stylesheet">
	<link href="css/jquery.gritter.css" rel="stylesheet">

	<!-- HTML5 shim and Respond.js IE8 support of HTML5 elements and media queries -->
	<!--[if lt IE 9]>
	<script src="js/html5shiv.js"></script>
	<script src="js/respond.min.js"></script>
	<![endif]-->
</head>

<body>
	<!-- Preloader -->
	<div id="preloader">
		<div id="status"><i class="fa fa-envelope-o fa-spin"></i></div>
	</div>

	<section>
		<div class="leftpanel">
			<div class="logopanel">
				<h1><span>[</span> email<span>-</span>parser<span>.</span>py <span>]</span></h1>
			</div><!-- logopanel -->

			<!-- <h5 class="sidebartitle">Navigation</h5> -->
			<ul class="nav nav-pills nav-stacked nav-bracket">
				<li class="active"><a href="#"><i class="fa fa-home"></i> <span>Dashboard</span></a></li>
				<li><a href="tables.php"><i class="fa fa-database"></i> <span>Database</span></a></li>
				<li><a href="inc/submit-indicator.html" data-toggle="modal" data-target=".external-modal"><i class="fa fa-crosshairs"></i> <span>Submit Indicator</span></a></li>
				<li><a href="#" data-toggle="modal" data-target=".upload-modal"><i class="fa fa-upload"></i> <span>Upload PCAP</span></a></li>
				<li><a href="suspicion.html" data-toggle="modal" data-target=".external-modal-lg"><i class="fa fa-question"></i> <span>How Suspicion Works</span></a></li>
			</ul>

			<div class="infosummary">
				<h5 class="sidebartitle">Other Stats</h5>
				<ul>
					<li>
						<div class="datainfo">
							<span class="text-muted">DATABASE SIZE</span>
							<h4><?php echo $dbsize;?> MB</h4>
						</div>
					</li>
					<li>
						<div class="datainfo">
							<span class="text-muted">TOTAL ATTACHMENTS IN DATABASE</span>
							<h4><?php echo $totalattachments;?></h4>
						</div>
					</li>
					<li>
						<div class="datainfo">
							<span class="text-muted">TOTAL ANALYZED ATTACHMENTS</span>
							<h4><?php echo $totalanalyzed;?></h4>
						</div>
					</li>
				</ul>
			</div>

			<div class="infosummary">
				<h5 class="sidebartitle">Server Status</h5>
				<ul>
					<li>
						<span class="sublabel">CPU Usage (<?php echo sprintf("%d", $currentcpuusage);?>%)</span>
						<div class="progress progress-sm">
							<div style="width: <?php echo $currentcpuusage; ?>%" aria-valuemax="100" aria-valuemin="0" aria-valuenow="40" role="progressbar" class="progress-bar <?php echo get_progress_bar_style($currentcpuusage); ?>"></div>
						</div><!-- progress -->
					</li>
					<li>
						<span class="sublabel">Memory Usage (<?php echo sprintf("%d", $currentmemusage);?>%)</span>
						<div class="progress progress-sm">
							<div style="width: <?php echo $currentmemusage; ?>%" aria-valuemax="100" aria-valuemin="0" aria-valuenow="40" role="progressbar" class="progress-bar <?php echo get_progress_bar_style($currentmemusage); ?>"></div>
						</div><!-- progress -->
					</li>
					<li>
						<span class="sublabel">Disk Usage (<?php echo sprintf("%d", $currenthddusage);?>%)</span>
						<div class="progress progress-sm">
							<div style="width: <?php echo $currenthddusage; ?>%" aria-valuemax="100" aria-valuemin="0" aria-valuenow="40" role="progressbar" class="progress-bar <?php echo get_progress_bar_style($currenthddusage); ?>"></div>
						</div><!-- progress -->
					</li>
				</ul>
			</div><!-- infosummary -->
		</div><!-- leftpanel -->

		<div class="mainpanel">
			<div class="headerbar">
					<a class="menutoggle"><i class="fa fa-envelope-o"></i></a>
				</div><!-- headerbar -->
				<div class="pageheader">
					<h2><i class="fa fa-home"></i> Dashboard <span>Pretty graphs and metrics!</span></h2>
					<div class="breadcrumb-wrapper">
						<span class="label">You are here:</span>
						<ol class="breadcrumb">
							<li><a href="index.html">email-parser</a></li>
							<li class="active">Dashboard</li>
						</ol>
					</div>
				</div>
				<div class="contentpanel">
					<!-- content goes here... -->
					<div class="row">
						<div class="col-md-5">
							<div class="panel panel-dark panel-stat">
								<div class="panel-heading">
									<div class="stat" style="max-width:inherit;">
										<div class="row">
											<div class="col-md-3">
												<img src="images/is-user.png" alt="" />
											</div>
											<div class="col-md-9">
												<small class="stat-label">TOTAL EMAILS IN DATABASE</small>
												<h1><?php echo $totalemails; ?></h1>
											</div>
										</div><!-- row -->
										<div class="mb15"></div>
										<div class="row">
											<div class="col-md-6">
												<small class="stat-label">UNIQUE SENDER IPS</small>
												<h4><?php echo $uniqips; ?></h4>
											</div>
											<div class="col-md-6">
												<small class="stat-label">UNIQUE ATTACHMENTS</small>
												<h4><?php echo $totalattachments; ?></h4>
											</div>
										</div><!-- row -->
									</div><!-- stat -->
								</div><!-- panel-heading -->
							</div><!-- panel -->
						</div><!-- col-md-3 -->

						<div class="col-md-5">
							<div class="panel panel-primary panel-stat">
								<div class="panel-heading">
									<div class="stat" style="max-width:inherit;">
										<div class="row">
											<div class="col-md-3">
												<img src="images/is-document.png" alt="" />
											</div>
											<div class="col-md-9">
												<small class="stat-label">Last Database Entry</small>
												<h4><?php echo $lastinput;?></h4>
											</div>
										</div><!-- row -->
										<div class="mb15"></div>
										<small class="stat-label">This long ago:</small>
										<?php echo $lastinputago;?>
									</div><!-- stat -->
								</div><!-- panel-heading -->
							</div><!-- panel -->
						</div><!-- col-md-3 -->
					</div><!-- row -->

					<div class="row">
						<div class="col-md-5">
							<div class="panel panel-danger panel-stat">
								<div class="panel-heading">
									<div class="stat" style="max-width:inherit;">
										<div class="row">
											<div class="col-md-3">
												<img src="images/is-document.png" alt="" />
											</div>
											<div class="col-md-9">
												<small class="stat-label">SUSPICIOUS ATTACHMENTS</small>
												<h1><?php echo $attachmentcount; ?></h1>
											</div>
										</div><!-- row -->
										<div class="mb15"></div>
										<small class="stat-label">THE MOST SUSPICIOUS FILE</small>
										<pre><?php
										echo 'SUSPICION: ', $highestsuspicion, PHP_EOL;
										echo ' FILENAME: ', $attachmentmostsuspicious, PHP_EOL;
										echo ' CHECKSUM: ', $attachmentmostsuspiciousmd5; ?></pre>
										<div class="btn-group">
											<button type="button" class="btn btn-default btn-xs">Action</button>
											<button type="button" class="btn btn-default btn-xs dropdown-toggle" data-toggle="dropdown">
												<span class="caret"></span>
												<span class="sr-only">Toggle Dropdown</span>
											</button>
											<ul class="dropdown-menu" role="menu">
												<?php
												echo '<li><a href="inc/getfile.php?md5=', $attachmentmostsuspiciousmd5 . '">Download File</a></li>';
												echo '<li><a href="inc/submit.php?md5=', $attachmentmostsuspiciousmd5 . '" data-toggle="modal" data-target=".external-modal">Sandbox File</a></li>';
												?>
											</ul>
										</div><!-- btn-group -->
									</div><!-- stat -->
								</div><!-- panel-heading -->
							</div><!-- panel -->
						</div><!-- col-sm-6 -->

						<div class="col-md-5">
							<div class="panel panel-success panel-stat">
								<div class="panel-heading">
									<div class="stat" style="max-width:inherit;">
										<div class="row">
											<div class="col-md-3">
												<img src="images/is-user.png" alt="" />
											</div>
											<div class="col-md-9">
													<small class="stat-label">Most targeted email</small>
													<h4><?php echo $most_targeted; ?></h4>
											</div>
										</div><!-- row -->
										<div class="mb15"></div>
										<small class="stat-label">ADDRESS RECEIVED THESE ATTACHMENTS:</small>
										<select class="form-control input-sm">
											<?php	foreach($attachments as $attachment) { echo "<option value=" . $attachment['md5'] . ">" . $attachment['name'] . "</option>", PHP_EOL; } ?>
										</select>
									</div><!-- stat -->
								</div><!-- panel-heading -->
							</div><!-- panel -->
						</div><!-- col-md-3 -->
					</div><!-- row -->

					<div class="row">
						<div class="col-sm-10">
							<div class="panel panel-primary panel-alt">
								<div class="panel-heading">
									<h3 class="panel-title">VISUALIZATION</h3>
									<p>This graph shows a quick visualization of how many emails we process. The user should be able to identify phishing campaigns by the peaks in this graph</p>
								</div>
								<div class="panel-body">
									<div class="row">
										<div class="col-sm-8">
											<div id="basicflot" style="width: 100%; height: 375px;"></div>
										</div><!-- col-sm-8 -->
										<div class="col-sm-4">
											<h5 class="subtitle mb5">Graph Query</h5>
											<p class="mb15">Change the graph on the left</p>
											<form action="index.php">
												<div class="rdio rdio-primary">
													<input type="radio" name="graph" value="hourly" id="graphhourly" />
													<label for="graphhourly">24 hours</label>
												</div>
												<div class="rdio rdio-primary">
													<input type="radio" name="graph" value="daily" id="graphdaily" />
													<label for="graphdaily">30 days</label>
												</div>
												<div class="rdio rdio-primary">
													<input type="radio" name="graph" value="weekly" id="graphweekly" />
													<label for="graphweekly">8 weeks</label>
												</div>
												<div class="rdio rdio-primary">
													<input type="radio" name="graph" value="monthly" id="graphmonthly" />
													<label for="graphmonthly">1 year (monthly)</label>
												</div>
												<button class="btn btn-primary">Submit!</button>
											</form>

											<h5 style="margin-top:20px;" class="subtitle mb5">Top 10 Sender Domains</h5>
											<div id="domain-donut" class="ex-donut-chart"></div>
										</div><!-- col-sm-4 -->
									</div><!-- row -->
								</div><!-- panel-body -->
							</div><!-- panel -->
						</div><!-- col-sm-10 -->
					</div><!-- row -->
			</div><!-- contentpanel -->
		</div><!-- mainpanel -->
	</section>

	<div id="externalmodal" class="modal fade external-modal" tabindex="-1" role="dialog" aria-hidden="true">
		<div class="modal-dialog">
			<div class="modal-content"></div>
		</div>
	</div>

	<div id="externalmodal-lg" class="modal fade external-modal-lg" tabindex="-1" role="dialog" aria-hidden="true">
		<div class="modal-dialog modal-lg">
			<div class="modal-content"></div>
		</div>
	</div>

	<div class="modal fade upload-modal" tabindex="-1" role="dialog" aria-hidden="true">
		<div class="modal-dialog">
			<div class="modal-content">
				<div class="modal-header">
					<button aria-hidden="true" data-dismiss="modal" class="close" type="button">&times;</button>
					<h4 class="modal-title"><i class="fa fa-upload" style="margin-right:15px;"></i>Multiple File Upload</h4>
				</div>
				<div class="modal-body">
					<form method="POST" action="inc/upload.php" class="dropzone" enctype="multipart/form-data" id="my-awesome-dropzone"></form>
				</div>
			</div>
		</div>
	</div>

	<script src="js/jquery-1.11.1.min.js"></script>
	<script src="js/jquery-migrate-1.2.1.min.js"></script>
	<script src="js/bootstrap.min.js"></script>
	<script src="js/modernizr.min.js"></script>
	<script src="js/jquery.sparkline.min.js"></script>
	<script src="js/toggles.min.js"></script>
	<script src="js/retina.min.js"></script>
	<script src="js/jquery.cookies.js"></script>
	<script src="js/dropzone.js"></script>
	<script src="js/jquery.gritter.min.js"></script>

	<script src="js/flot/jquery.flot.min.js"></script>
	<script src="js/flot/jquery.flot.resize.min.js"></script>
	<script src="js/flot/jquery.flot.spline.min.js"></script>

	<script src="js/custom.js"></script>
	<script src="js/select2.min.js"></script>
	<script src="js/morris.min.js"></script>
	<script src="js/raphael-2.1.0.min.js"></script>
	<script type="text/javascript">
	function showTooltip(x, y, contents) {
		jQuery('<div id="tooltip" class="tooltipflot">' + contents + '</div>').css( {
			position: 'absolute',
			display: 'none',
			top: y + 5,
			left: x + 5
			}).appendTo("body").fadeIn(200);
	}

		$("#externalmodal").on('hidden.bs.modal', function () {
			$(this).data('bs.modal', null);
		});

		// Donut Chart
		var m1 = new Morris.Donut({
			element: 'domain-donut',
			data: [

				<?php
				foreach ($domains as $domain) {
					echo '{label: "', $domain['domain'], '", value: ', $domain['count'], '},', PHP_EOL;
				}
				?>

			],
			colors: ['#D9534F','#1CAF9A','#428BCA','#5BC0DE','#428BCA']
		});

		var emails = [<?php
			foreach ($time_graph as $tg) {
				echo '[', $tg['time'], ', ', $tg['count'], '], ';
			}
			?>];

		var downloads = [[0, 0], [1, 6.5], [2,4], [3, 10], [4, 2], [5, 10], [6, 4]];

		var plot = jQuery.plot(jQuery("#basicflot"),
		[
		{ data: emails,
			label: "Emails",
			color: "#428BCA"
		}],
		{
			series: {
				lines: {
					show: true
				},
				splines: {
					show: true,
					tension: 0.5,
					lineWidth: 1,
					fill: 0.45
				},
				shadowSize: 0
			},
			points: {
				show: true
			},
			legend: {
				position: 'nw'
			},
			grid: {
				hoverable: true,
				clickable: true,
				borderColor: '#ddd',
				borderWidth: 1,
				labelMargin: 10,
				backgroundColor: '#fff'
			},
			yaxis: {
				min: 0,

				color: '#eee'
			},
			xaxis: {
				color: '#eee',
				//min: 0,
				//max: 23,
				tickSize: 1,
				tickDecimals: 0
			}
		});

		var previousPoint = null;
		jQuery("#basicflot").bind("plothover", function (event, pos, item) {
			jQuery("#x").text(pos.x.toFixed(2));
			jQuery("#y").text(pos.y.toFixed(2));

			if(item) {
				if (previousPoint != item.dataIndex) {
					previousPoint = item.dataIndex;

					jQuery("#tooltip").remove();
					var x = item.datapoint[0].toFixed(2),
					y = item.datapoint[1].toFixed(2);

					showTooltip(item.pageX, item.pageY, y + " emails");
					}

				} else {
					jQuery("#tooltip").remove();
					previousPoint = null;
				}

			});
	</script>
</body>
</html>

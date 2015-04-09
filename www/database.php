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
	<link href="css/style.darkknight.css" rel="stylesheet">
	<link href="css/jquery.datatables.css" rel="stylesheet">
	<link href="css/dataTables.tableTools.css" rel="stylesheet">
	<link href="css/dropzone.css" rel="stylesheet">
	<link href="css/jquery.gritter.css" rel="stylesheet">


	<!-- HTML5 shim and Respond.js IE8 support of HTML5 elements and media queries -->
	<!--[if lt IE 9]>
	<script src="js/html5shiv.js"></script>
	<script src="js/respond.min.js"></script>
	<![endif]-->
	<!-- Needed to keep the datepicker on top of the modal (popup) -->
	<style>
		td.details-control {
			background: url('images/details_open.png') no-repeat center center;
			cursor: pointer;
			}
		tr.details td.details-control {
			background: url('images/details_close.png') no-repeat center center;
			}
		table.dataTable {
			border-collapse: collapse;
			width: 100% !important;
		}
		<!-- Needed to keep the datepicker on top of the modal (popup) -->
		.ui-datepicker{ z-index:1151 !important; }

		pre {
			width: 800px;
	    white-space: pre-wrap;       /* CSS 3 */
	    white-space: -moz-pre-wrap;  /* Mozilla, since 1999 */
	    white-space: -pre-wrap;      /* Opera 4-6 */
	    white-space: -o-pre-wrap;    /* Opera 7 */
	    word-wrap: break-word;       /* Internet Explorer 5.5+ */
			}
	</style>
</head>
<body class="horizontal-menu">
	<!-- Preloader -->
	<div id="preloader">
		<div id="status"><i class="fa fa-envelope-o fa-spin"></i></div>
	</div>

	<section>
		<div class="mainpanel">
			<div class="headerbar">
				<div class="headerbar-left">
					<div class="logopanel">
						<h1><span>[</span> email<span>-</span>parser<span>.</span>py <span>]</span></h1>
					</div><!-- logopanel -->
					<div class="topnav">
						<a class="menutoggle"><i class="fa fa-envelope-o"></i></a>
						<ul class="nav nav-horizontal">
							<li><a href="index.php"><i class="fa fa-home"></i><span>Dashboard</span></a></li>
							<li class="active"><a href="#"><i class="fa fa-database"></i><span>Database</span></a></li>
							<li><a href="targets.php"><i class="fa fa-bullseye"></i><span>Target Database</span></a></li>
							<li><a href="inc/submit-indicator.html" data-toggle="modal" data-target=".external-modal"><i class="fa fa-crosshairs"></i> <span>Submit Target</span></a></li>
							<li><a href="#" data-toggle="modal" data-target=".upload-modal"><i class="fa fa-upload"></i> <span>Upload PCAP</span></a></li>
							<li><a href="suspicion.html" data-toggle="modal" data-target=".external-modal-lg"><i class="fa fa-question"></i> <span>How Suspicion Works</span></a></li>
						</ul>
					</div>
				</div>
			</div><!-- headerbar -->

			<div class="pageheader">
				<h2><i class="fa fa-database"></i> Database <span>A quick look at the emails in your database</span></h2>
				<div class="breadcrumb-wrapper">
					<span class="label">You are here:</span>
					<ol class="breadcrumb">
						<li><a href="index.html">email-parser</a></li>
						<li class="active">Database Query</li>
					</ol>
				</div>
			</div>

			<div class="contentpanel">
				<!-- <div class="clearfix mb30"></div>
				<div class="input-group col-sm-3">
					<input type="text" placeholder="SELECT * FROM email WHERE attachment_ref.name LIKE '%bad%'" id="sqlquery" class="form-control" disabled=""/>
					<span class="input-group-btn"><button type="button" class="btn btn-default">Go!</button></span>
				</div>
				<div class="clearfix mb30"></div>-->
				<div class="table-responsive">
					<table id="the_table" class="table table-striped">
						<thead>
							<tr>
								<th></th>
								<th width="10%">Timestamp</th>
								<th></th>
								<th>Source IP</th>
								<th>Sender</th>
								<th>Subject</th>
								<th>Attachment</th>
								<th>Suspicion</th>
								<th>Checksum</th>
								<th>#</th>
							</tr>
						</thead>
						<tbody></tbody>
					</table>
				</div><!-- table-responsive -->
			</div>
		</div><!-- mainpanel -->
	</section>

	<div id="externalmodal" class="modal fade external-modal" tabindex="-1" role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
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
					<h4 class="modal-title">Multiple File Upload</h4>
				</div>
				<div class="modal-body">
					<form method="POST" action="inc/upload.php" class="dropzone" enctype="multipart/form-data" id="my-awesome-dropzone"></form>
				</div>
			</div>
		</div>
	</div>

	<script src="js/jquery-1.11.1.min.js"></script>
	<script src="js/jquery-migrate-1.2.1.min.js"></script>
	<script src="js/jquery-ui-1.10.3.min.js"></script>
	<script src="js/bootstrap.min.js"></script>
	<script src="js/modernizr.min.js"></script>
	<script src="js/retina.min.js"></script>

	<script src="js/dropzone.js"></script>
	<script src="js/jquery.datatables.min.js"></script>
	<script src="js/dataTables.tableTools.js"></script>
	<script src="js/select2.min.js"></script>
	<script src="js/jquery.gritter.min.js"></script>

	<script src="js/custom.js"></script>
	<script type="text/javascript">
		$("#externalmodal").on('hidden.bs.modal', function () {
			$(this).data('bs.modal', null);
		});

		function format ( d ) {
			return '<h4>Email Details</h4>' +
			'<pre>' +
			'Subject:     ' + d.subject + '<br />' +
			'Recipient:   ' + d.recipient + '<br />' +
			'IPAddr:      ' + d.ip_src + '<br />' +
			'TCP Port:    ' + d.tcp_sport + '<br />' +
			'Location:    <img src="flags/' + d.digraph + '.png"> ' + d.country + '<br />' +
			'MD5sum:     <span title="Send to Sandbox" style="margin-left:10px;" data-placement="top" data-toggle="tooltip" class="tooltips"><a data-toggle="modal" data-target=".external-modal" href="inc/submit-cuckoo.php?md5=' + d.md5 + '">' + d.md5 + '</a></span><br />' +
			'SSDeep:      ' + d.ssdeep + '<br />' +
			'Attachment: <span title="Download Attachment" style="margin-left:10px;" data-placement="top" data-toggle="tooltip" class="tooltips"><a href="inc/getfile.php?md5=' + d.md5 + '">' + d.name + '</a></span><br />' +
			'Message body: <br /><xmp>' +
			d.message_body + '</xmp></pre><br />' +
			'<div class="btn-group">' +
			'<button type="button" class="btn btn-default btn-xs">Email Actions</button>' +
			'<button type="button" class="btn btn-default btn-xs dropdown-toggle" data-toggle="dropdown">' +
			'<span class="caret"></span>' +
			'<span class="sr-only">Toggle Dropdown</span>' +
			'</button>' +
			'<ul class="dropdown-menu" role="menu">' +
			'<li><a href="inc/getfile.php?md5=12345">Retain email</a></li>' +
			'<li><a href="inc/submit.php?md5=12345" data-toggle="modal" data-target=".external-modal">Delete email</a></li>' +
			'</ul>' +
			'</div>';
		};

		$(document).ready(function() {
			var dt = $('#the_table').DataTable( {
				dom: 'Tlf<"clear">rtip',
				"serverSide": true,
				"processing": true,
				"ajax": "inc/ajax-database.php",
				"columns": [
					{
					"className":      'details-control',
					"orderable":      false,
					"data":           null,
					"defaultContent": ''
					},
					{ "data": "timestamp" },
					{ "data": "country" },
					{ "data": "ip_src" },
					{ "data": "sender" },
					{ "data": "subject" },
					{ "data": "name" },
					{ "data": "suspicion" },
					{ "data": "count" }
					],
					"order": [[1, 'asc']],
				"fnRowCallback": function( nRow, aData, iDisplayIndex ) {
					$('td:eq(2)', nRow).html('<img style="margin-left:5px;" src="flags/' + aData['digraph'] + '.png" />');
					// $('td:eq(6)', nRow).html('<span title="Download Attachment" style="margin-left:10px;" data-placement="top" data-toggle="tooltip" class="tooltips"><a href="inc/getfile.php?md5=' + aData[8] + '">' + aData['md5'] + '</a></span>');
					return nRow;
				},
				tableTools: {
					"sSwfPath": "swf/copy_csv_xls_pdf.swf"
				}
			});

		// Array to track the ids of the details displayed rows
		var detailRows = [];

		$('#the_table tbody').on( 'click', 'tr td:first-child', function () {
			var tr = $(this).closest('tr');
			var row = dt.row( tr );
			var idx = $.inArray( tr.attr('id'), detailRows );

			if ( row.child.isShown() ) {
					tr.removeClass( 'details' );
					row.child.hide();

					// Remove from the 'open' array
					detailRows.splice( idx, 1 );
			}
			else {
					tr.addClass( 'details' );
					row.child( format( row.data() ) ).show();

					// Add to the 'open' array
					if ( idx === -1 ) {
							detailRows.push( tr.attr('id') );
					}
			}
		} );

		// On each draw, loop over the `detailRows` array and show any child rows
		dt.on( 'draw', function () {
			$.each( detailRows, function ( i, id ) {
					$('#'+id+' td:first-child').trigger( 'click' );
			} );
		} );

		});


		// Select2
		$('select').select2({
			minimumResultsForSearch: -1
		});

		$('select').removeClass('form-control');

		// Delete row in a table
		$('.delete-row').click(function(){
			var c = confirm("Continue delete?");
			if(c)
			$(this).closest('tr').fadeOut(function(){
				$(this).remove();
			});
			return false;
		});

		// Show aciton upon row hover
		$('.table-hidaction tbody tr').hover(function(){
			$(this).find('.table-action-hide a').animate({opacity: 1});
		},function(){
			$(this).find('.table-action-hide a').animate({opacity: 0});
		});
	</script>
</body>
</html>

'use strict';

var Cvss = require('Cvss');

exports.error = function (err, args) {
	console.error(err.message);
};

// Purposely do nothing
exports.success = function (result, args) {
};

exports.check = {};
exports.check.success = function (result, args) {

	var pipeWrap = function (items) {
		return '|' + items.join('|') + '|';
	};

	var header = [
		'Severity',
		'Title',
		'Module',
		'Installed',
		'Patched',
		'Include Path',
		'More Info'
	];

	var rows = [];
	rows.push( pipeWrap(header) );
	rows.push( pipeWrap( Array(header.length).fill('--') ) );

	result.data.forEach( (finding) => {
		var advisory_number
			= finding.advisory.substr(finding.advisory.lastIndexOf('/'));

		// Pipe characters cannot be escaped within
		// Remarkup tables so replace with OR
		var patched_versions
			= finding.patched_versions === '<0.0.0'
				? 'None'
				: finding.patched_versions.replace(/\|\|/g, 'OR');

		rows.push(
			pipeWrap([
				Cvss.getRating(finding.cvss_score),
				finding.title,
				finding.module,
				finding.version,
				patched_versions,
				'{nav ' + finding.path.join(' > ') + '}',
				'[[' + finding.advisory + '|nspa' + advisory_number + ']]'
			])
		);
	});

	console.log( rows.join('\n') );
};

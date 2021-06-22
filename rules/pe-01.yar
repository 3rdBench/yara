rule pe
{
	meta:
		author = "Benjie Lazaro III"
		description = "Checks for existence of a PE signature (i.e. MZ or 4D 5A) in a file at offset 0"

	strings:
		$a = { 4D 5A }

	condition:
		$a at 0
}
rule pe
{
	meta:
		author = "Benjie Lazaro III"
		description = "Checks for existence of a PE signature (i.e. MZ) in a file at offset 0"

	strings:
		$a = "MZ"

	condition:
		$a at 0
}
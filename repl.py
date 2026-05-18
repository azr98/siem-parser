import re

print(re.findall(r"'(.*?)" , " code: 'PGRST116'"))
print(re.findall(r"'(.*?)" , " hint: null,'"))
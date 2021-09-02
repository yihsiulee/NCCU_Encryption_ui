def split_num(num, group_num):
    '''split number into list'''
    tmp = str(num)
    return [tmp[i:i+group_num] for i in range(0, len(tmp), group_num)]

def merge_num(num_list):
    '''merge the number list into int'''
    result = ''
    for n in num_list:
        result += n.rjust(4, '0')
    return result

def combine(target, start, num):
    result = []
    for i in range(num):
        tmp = 0
        for n in target[start+1:start + target[start] + 1]:
            tmp = tmp * 10 + n
        result.append(tmp)
        start = start + target[start] + 1
    return result
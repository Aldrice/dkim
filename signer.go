package dkim

// Signer for DKIM Version 1
type Signer struct {
}

func NewSigner() *Signer {
	v := &Signer{}
	return v
}

/*
TODO Signer设计需求:
	5.1 决定是否应该被签署, 以及应该以谁的名义来签署
		1. 签名的过程必须按照文档中写明的顺序执行
		2. submission server在签名时, 若发现某邮件的Received标头被混淆时, 则在签名时不应该包括Received标头
		3. 当某邮件由于某些原因不能生成签名时, 应该由部署方的配置去决定是否签名
	5.2 选择一个合适的密钥和对应的Selector信息
		1. 选择哪个selector去签署应该由部署方按照某些策略来决定
		2. Signer不应该用一个对应公钥即将被废除的私钥去签名
		3. Verifier可能会推迟对某些邮件的验证, 比如仅会在该邮件被阅读时才开始验证, 在此期间若换用了新密钥对, Signer应当立即开始使用新密钥对,
		而旧公钥应该在按照规定的时间间隔保存一段时间后才被移除。
	5.3 将邮件进行标准化(Normalize)以避免传输过程中的变化导致签名无效
		1. 存在一种转化, 把邮件中可能会导致内容变更的格式转化为更稳定的形式, 这部分的改变和签名时的语义化不一样, 因为这种改变是在签名前进行的
		2. 实际用于签名的邮件本体长度应该被计入到'l='tag中, l=0则意味着该邮件从未被签名
	5.4 决定邮件的哪些标头参与签名
		1. 'From' 必须参与签名
		2. 由于一部分Verifier可能会把未参与签名的标头给隐去, 因此作为一个Signer应该尽可能的把有效的标头加入到签名当中
		3. 延续2, 因此推荐'Date', 'Subject', 'Reply-To', 'Sender' 和所有MIME标头参与签名
		4. 要生成的DKIM签名本身绝对不能被包括进'h='标签中, 除非是其它已经存在的DKIM签名
		5. 当'h='标签中声明了不存在的标头, 则签名时应该把该标头的值(标头名, 冒号分隔符, 标头值和尾部的CRLF)都当做空值处理
		6. 'h='标签中重复声明是允许的
		7. Signer应该把所有用户可以看到的显式标头加入签名, 以应对间接垃圾邮件(indirect spamming)的威胁
		8. 当'l='标签不为空时, 应当把Content-Type也用于签名
		9. 延续3, 参与签名的理想标头有: 'From', 'Reply-To', 'Subject', 'Date', 'To', 'Cc', 'Resent-Date', 'Resent-From',
		'Recent-To', 'Recent-Cc', 'In-Reply-To', 'References', 'List-Id, List-Help...' 等等
		10.尽量不要选择那些会在传输过程中被修改的标头, 如: 'Return-Path', 'Received', 'Comments', 'Keywords' 等等
		11.尽量不要选用可选标头用于签名
		12.当Signer签名时发现某个指定的标头类型存在多个标头实体, 那么应当选用最后一个实体参与签名
		13.当邮件里存在同一类型但实体数量多于一的标头, 并且Signer希望将这些标头全部签署进去, 则应当在'h='标签里连续声明多次该类型, 具体例子参考文档
	5.5 计算邮件的Hash和签名
		1. 必须按照section3.7中的描述生成相应数据
		2. 例如mailing list manager等实体在使用DKIM进行签名生成时, 有额外的注意事项, 具体看section5.5
	5.6 将生成的DKIM签名插入到邮件中
		1. Signer应该在邮件被发出去之前插入生成的DKIM邮件
*/

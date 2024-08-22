package tree

type Node[T any] struct {
	value T
	left  *Node[T]
	right *Node[T]
}

func NewNode[T any](value T) *Node[T] {
	return &Node[T]{value: value}
}

func Insert[T any](root *Node[T], value T, isLeft func(a, b T) bool) *Node[T] {
	if root == nil {
		return NewNode(value)
	}
	if isLeft(value, root.value) {
		root.left = Insert(root.left, value, isLeft)
	} else {
		root.right = Insert(root.right, value, isLeft)
	}
	return root
}

func InOrderTraversal[T any](root *Node[T], list *[]T) {
	if root == nil {
		return
	}
	InOrderTraversal(root.left, list)
	*list = append(*list, root.value)
	InOrderTraversal(root.right, list)
}
